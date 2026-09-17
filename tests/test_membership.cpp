#include <algorithm>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

MPF_TEST(exact_duplicate_path_membership_is_rejected) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("duplicate", 1, 2);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("path-duplicate-extra", 1).succeeded());
  MPF_REQUIRE(fixture.add_member(set_id, "path-duplicate-extra", 1).succeeded());

  // The exact same PathId may appear at most once in a current set.
  const FabricOutcome duplicate = fixture.add_member(set_id, "path-duplicate-0", 1);
  MPF_CHECK(!duplicate.succeeded());
  MPF_CHECK_EQ(duplicate.code, OutcomeCode::DUPLICATE_MEMBER);

  // The duplicate did not silently count twice toward the threshold.
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{3});
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{3});

  // A duplicate inside one bulk publication is rejected as well and the whole
  // batch is refused: bulk publication is all or nothing.
  std::vector<MemberRequest> batch(2);
  batch[0].path_id = PathId::require("path-duplicate-0");
  batch[0].authority_generation = PathAuthorityGeneration::require(1);
  batch[1].path_id = PathId::require("path-duplicate-0");
  batch[1].authority_generation = PathAuthorityGeneration::require(1);
  const FabricOutcome bulk = fixture.engine().add_members(fixture.context(), set_id, batch);
  MPF_CHECK(!bulk.succeeded());
  MPF_CHECK_EQ(bulk.code, OutcomeCode::DUPLICATE_MEMBER);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->generation.value(), snapshot->generation.value());
}

MPF_TEST(reordered_publication_produces_identical_state) {
  // Every permutation of a three-member publication produces the same canonical
  // membership representation, the same usable count, the same readiness and
  // the same explanation ordering. The semantic digest also covers the set
  // identity and key, so it is compared for repeated reads of one set rather
  // than across two distinct sets.
  const std::vector<std::string> paths = {"path-perm-a", "path-perm-b", "path-perm-c"};
  std::vector<std::size_t> order = {0, 1, 2};
  std::string reference_members;
  std::string reference_explanation;
  std::size_t iteration = 0;
  do {
    mpf_test::FabricFixture fixture;
    const MultipathSetId set_id = fixture.create_set("permutation", 1);
    MPF_REQUIRE(set_id.valid());
    MPF_REQUIRE(fixture.publish(set_id).succeeded());
    for (const std::size_t index : order) {
      MPF_REQUIRE(fixture.declare(paths[index], 1).succeeded());
      MPF_REQUIRE(fixture.add_member(set_id, paths[index], 1).succeeded());
    }
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    MPF_CHECK_EQ(snapshot->members.size(), std::size_t{3});
    MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{3});
    MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
    MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::READY);

    // Canonical member representation: ordering plus the fields that describe
    // the governed membership, excluding per-incarnation provenance.
    std::string members;
    for (const auto& member : snapshot->members) {
      members += member.path_id.str();
      members += '|';
      members += std::to_string(member.bound_authority_generation.value());
      members += '|';
      members += std::string(to_string(member.lifecycle));
      members += '|';
      members += std::string(to_string(member.currentness));
      members += '|';
      members += member.admin_enabled ? "1" : "0";
      members += '\n';
    }
    // The digest is stable for repeated reads of the identical state.
    const auto again = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(again.has_value());
    MPF_CHECK_EQ(again->digest.to_hex(), snapshot->digest.to_hex());

    const auto explanation = fixture.engine().explain_set(set_id);
    MPF_REQUIRE(explanation.has_value());
    std::string reasons;
    for (const auto reason : explanation->reasons) {
      reasons += std::string(to_string(reason));
      reasons += ' ';
    }
    reasons += '|';
    for (const auto& member : explanation->members) {
      reasons += member.path_id.str();
      reasons += ':';
      reasons += std::string(to_string(member.reason));
      reasons += ' ';
    }

    if (iteration == 0) {
      reference_members = members;
      reference_explanation = reasons;
    } else {
      MPF_CHECK_EQ(members, reference_members);
      MPF_CHECK_EQ(reasons, reference_explanation);
    }
    ++iteration;
  } while (std::next_permutation(order.begin(), order.end()));
  MPF_CHECK_EQ(iteration, std::size_t{6});
}

MPF_TEST(member_removal_is_distinct_from_invalidation) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("removal", 1, 2);
  MPF_REQUIRE(set_id.valid());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;

  const FabricOutcome removed =
      fixture.engine().remove_member(fixture.context(), set_id, member_id, "administrative");
  MPF_CHECK(removed.succeeded());
  MPF_CHECK_EQ(removed.code, OutcomeCode::MEMBER_REMOVED);

  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{1});
  MPF_CHECK(snapshot->find_member(member_id) == nullptr);

  // The same exact path can be re-admitted after administrative removal.
  const FabricOutcome readmitted = fixture.add_member(set_id, "path-removal-0", 1);
  MPF_CHECK(readmitted.succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{2});

  // Removing an unknown member identity is a structured rejection.
  const MultipathMemberId unknown = MultipathMemberId::require("no-such-member");
  const FabricOutcome missing =
      fixture.engine().remove_member(fixture.context(), set_id, unknown, "x");
  MPF_CHECK_EQ(missing.code, OutcomeCode::MEMBER_NOT_FOUND);
}

MPF_TEST(member_withdrawal_preserves_the_record_and_lineage) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("withdraw", 1, 2);
  MPF_REQUIRE(set_id.valid());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;

  const FabricOutcome withdrawn = fixture.engine().withdraw_member(
      fixture.context(), set_id, member_id, "path drained");
  MPF_CHECK(withdrawn.succeeded());
  MPF_CHECK_EQ(withdrawn.code, OutcomeCode::MEMBER_WITHDRAWN);

  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MemberSnapshot* member = snapshot->find_member(member_id);
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK_EQ(member->lifecycle, MemberLifecycle::WITHDRAWN);
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::SET_NOT_USABLE);
  MPF_CHECK(!member->usable);
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});

  // Readmitting the same path replaces the withdrawn relation and records the
  // lineage rather than silently mutating the old record.
  const FabricOutcome readmitted = fixture.add_member(set_id, "path-withdraw-0", 1);
  MPF_CHECK(readmitted.succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MemberSnapshot* successor = snapshot->find_member(PathId::require("path-withdraw-0"));
  MPF_REQUIRE(successor != nullptr);
  MPF_REQUIRE(successor->predecessor.has_value());
  MPF_CHECK_EQ(successor->predecessor->view(), member_id.view());
  MPF_CHECK(successor->usable);
}

MPF_TEST(member_replacement_records_full_lineage) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("replace", 1, 2);
  MPF_REQUIRE(set_id.valid());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId predecessor = snapshot->members.front().id;
  const PathId predecessor_path = snapshot->members.front().path_id;
  const MultipathMemberGeneration predecessor_generation = snapshot->members.front().generation;

  MPF_REQUIRE(fixture.declare("replace-successor", 1).succeeded());
  const FabricOutcome replaced =
      fixture.engine().replace_member(fixture.context(), set_id, predecessor,
                                      PathId::require("replace-successor"),
                                      PathAuthorityGeneration::require(1), "path migrated");
  MPF_CHECK(replaced.succeeded());
  MPF_CHECK_EQ(replaced.code, OutcomeCode::MEMBER_REPLACED);

  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MemberSnapshot* old_member = snapshot->find_member(predecessor);
  MPF_REQUIRE(old_member != nullptr);
  MPF_CHECK_EQ(old_member->lifecycle, MemberLifecycle::SUPERSEDED);
  MPF_CHECK(old_member->successor.has_value());
  MPF_CHECK(old_member->generation > predecessor_generation);
  const MemberSnapshot* new_member = snapshot->find_member(PathId::require("replace-successor"));
  MPF_REQUIRE(new_member != nullptr);
  MPF_CHECK_EQ(new_member->lifecycle, MemberLifecycle::CURRENT);
  MPF_CHECK(new_member->usable);
  MPF_REQUIRE(new_member->predecessor.has_value());
  MPF_CHECK_EQ(new_member->predecessor->view(), predecessor.view());
  MPF_CHECK(old_member->successor.has_value());
  MPF_CHECK_EQ(old_member->successor->view(), new_member->id.view());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});
  static_cast<void>(predecessor_path);

  // Replacing a member with its own path is refused: that is revalidation.
  const FabricOutcome same_path = fixture.engine().replace_member(
      fixture.context(), set_id, new_member->id, new_member->path_id,
      PathAuthorityGeneration::require(1), "same path");
  MPF_CHECK(!same_path.succeeded());
  MPF_CHECK_EQ(same_path.code, OutcomeCode::MALFORMED_REQUEST);
}

MPF_TEST(member_administrative_enablement_gates_usability) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("member-admin", 2, 3);
  MPF_REQUIRE(set_id.valid());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
  const MultipathMemberId member_id = snapshot->members.front().id;

  const FabricOutcome disabled = fixture.engine().set_member_admin_enabled(
      fixture.context(), set_id, member_id, false);
  MPF_CHECK(disabled.succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MemberSnapshot* member = snapshot->find_member(member_id);
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK(!member->admin_enabled);
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::ADMIN_DISABLED);
  MPF_CHECK(!member->usable);
  // 3 -> 2 usable is still at the requirement, so the set stays ACTIVE.
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);

  // Disabling one more member drops the set to DEGRADED.
  const MultipathMemberId second = snapshot->members[1].id;
  MPF_CHECK(fixture.engine()
                .set_member_admin_enabled(fixture.context(), set_id, second, false)
                .succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::DEGRADED);

  // Re-enabling is an explicit administrative re-evaluation.
  MPF_CHECK(fixture.engine()
                .set_member_admin_enabled(fixture.context(), set_id, second, true)
                .succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
}

MPF_TEST(set_administrative_disablement_never_reports_active) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("set-admin", 1, 2);
  MPF_REQUIRE(set_id.valid());
  const FabricOutcome disabled =
      fixture.engine().set_admin_enabled(fixture.context(), set_id, false);
  MPF_CHECK(disabled.succeeded());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ADMIN_DISABLED);
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::ADMIN_DISABLED);
  // The members remain individually authorized and current; administrative
  // intent is a distinct fact from path legality.
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});
  for (const auto& member : snapshot->members) {
    MPF_CHECK_EQ(member.currentness, MemberCurrentness::CURRENT);
  }

  const FabricOutcome enabled =
      fixture.engine().set_admin_enabled(fixture.context(), set_id, true);
  MPF_CHECK(enabled.succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::READY);
}

MPF_TEST(member_generation_conflicts_are_rejected) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("member-generation", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;

  MutationContext context = fixture.context();
  context.expected_member_generation = MultipathMemberGeneration::require(99);
  const FabricOutcome conflict =
      fixture.engine().remove_member(context, set_id, member_id, "stale view");
  MPF_CHECK(!conflict.succeeded());
  MPF_CHECK_EQ(conflict.code, OutcomeCode::STALE_MEMBER_GENERATION);

  const FabricOutcome wrong_set = [&]() {
    MutationContext other = fixture.context();
    other.expected_set_generation = MultipathSetGeneration::require(99);
    return fixture.engine().remove_member(other, set_id, member_id, "stale set view");
  }();
  MPF_CHECK(!wrong_set.succeeded());
  MPF_CHECK_EQ(wrong_set.code, OutcomeCode::STALE_SET_GENERATION);
}

MPF_TEST(bulk_publication_is_all_or_nothing) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("bulk", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  MPF_REQUIRE(fixture.declare("bulk-ok-1", 1).succeeded());
  MPF_REQUIRE(fixture.declare("bulk-ok-2", 1).succeeded());

  // The second entry has no Path Authority record, so the whole batch is refused
  // and nothing is committed.
  std::vector<MemberRequest> batch(2);
  batch[0].path_id = PathId::require("bulk-ok-1");
  batch[0].authority_generation = PathAuthorityGeneration::require(1);
  batch[1].path_id = PathId::require("bulk-missing");
  batch[1].authority_generation = PathAuthorityGeneration::require(1);
  const FabricOutcome refused = fixture.engine().add_members(fixture.context(), set_id, batch);
  MPF_CHECK(!refused.succeeded());
  MPF_CHECK_EQ(refused.code, OutcomeCode::PATH_AUTHORITY_UNKNOWN);
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{0});

  // A fully valid batch commits once and advances the membership generation once.
  batch[1].path_id = PathId::require("bulk-ok-2");
  const MembershipGeneration before = snapshot->membership_generation;
  const FabricOutcome committed = fixture.engine().add_members(fixture.context(), set_id, batch);
  MPF_CHECK(committed.succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{2});
  MPF_CHECK_EQ(snapshot->membership_generation.value(), before.value() + 1);
}

MPF_TEST(member_limit_is_enforced_on_every_path) {
  FabricConfig config;
  config.limits.max_members_per_set = 2;
  mpf_test::FabricFixture fixture;
  FabricEngine limited(config);
  const PublisherId publisher = PublisherId::require("limited-publisher");
  const WorkerBootId boot = WorkerBootId::require("limited-boot");
  const SessionId session = SessionId::require("limited-session");
  AuthorityScope scope;
  scope.fabric = FabricId::require("fabric-test");
  scope.name_space = MultipathNamespace::require("ns-test");
  MPF_REQUIRE(limited.register_publisher(publisher, boot, scope, session).succeeded());
  std::uint64_t attempts = 0;
  const auto context = [&]() {
    MutationContext value;
    value.epoch = limited.epoch();
    value.publisher = publisher;
    value.worker_boot = boot;
    value.session = session;
    value.attempt = MutationAttemptId::require("limited-attempt-" + std::to_string(++attempts));
    return value;
  };
  SetKey key;
  key.fabric = scope.fabric;
  key.name_space = scope.name_space;
  key.name = MultipathSetName::require("limited");
  SetOptions options;
  options.minimum_usable_members = 1;
  const FabricOutcome created = limited.create_set(context(), key, options);
  MPF_REQUIRE(created.succeeded());
  const MultipathSetId set_id = *created.set_id;
  MPF_REQUIRE(limited.publish_set(context(), set_id).succeeded());

  for (int index = 0; index < 2; ++index) {
    const std::string path = "limited-path-" + std::to_string(index);
    PathAuthorityView view;
    view.path = PathId::require(path);
    view.generation = PathAuthorityGeneration::require(1);
    view.state = PathAuthorityState::AUTHORIZED;
    MPF_REQUIRE(limited.declare_path_authority(context(), view).succeeded());
    MPF_REQUIRE(limited
                    .add_member(context(), set_id, view.path, view.generation)
                    .succeeded());
  }
  // Single add beyond the limit.
  PathAuthorityView overflow;
  overflow.path = PathId::require("limited-path-overflow");
  overflow.generation = PathAuthorityGeneration::require(1);
  overflow.state = PathAuthorityState::AUTHORIZED;
  MPF_REQUIRE(limited.declare_path_authority(context(), overflow).succeeded());
  const FabricOutcome rejected =
      limited.add_member(context(), set_id, overflow.path, overflow.generation);
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);

  // Bulk add beyond the limit.
  std::vector<MemberRequest> batch(1);
  batch[0].path_id = overflow.path;
  batch[0].authority_generation = overflow.generation;
  const FabricOutcome bulk_rejected = limited.add_members(context(), set_id, batch);
  MPF_CHECK(!bulk_rejected.succeeded());
  MPF_CHECK_EQ(bulk_rejected.code, OutcomeCode::RESOURCE_LIMIT);

  // Persistence restore beyond the limit.
  mpf_test::TempDirectory directory("member-limit");
  const std::string store = directory.path("store.bin");
  MPF_REQUIRE(limited.save_store(store).succeeded());
  FabricConfig relaxed;
  relaxed.limits.max_members_per_set = 1;
  FabricEngine constrained(relaxed);
  const FabricOutcome load = constrained.load_store(store);
  MPF_CHECK(!load.succeeded());
  MPF_CHECK_EQ(load.code, OutcomeCode::STORE_CORRUPT);
}