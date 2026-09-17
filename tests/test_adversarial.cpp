#include <algorithm>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

MPF_TEST(adversarial_malformed_identities_are_rejected_everywhere) {
  const std::vector<std::string> malformed = {
      "", " ", "a b", ".", "-", "a#", "#a", std::string(200, 'z'), "tab\there", "nl\nhere",
  };
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("malformed", 1, 1);
  MPF_REQUIRE(set_id.valid());

  for (const auto& text : malformed) {
    MPF_CHECK(!MultipathSetId::parse(text).has_value());
    MPF_CHECK(!PathId::parse(text).has_value());
    MPF_CHECK(!MultipathMemberId::parse(text).has_value());
    MPF_CHECK(!PublisherId::parse(text).has_value());
    MPF_CHECK(!WorkerBootId::parse(text).has_value());
    MPF_CHECK(!MutationAttemptId::parse(text).has_value());
    MPF_CHECK(!FabricId::parse(text).has_value());
    MPF_CHECK(!MultipathNamespace::parse(text).has_value());
    MPF_CHECK(!MultipathSetName::parse(text).has_value());
    MPF_CHECK(!SnapshotId::parse(text).has_value());
  }

  // A malformed set key never reaches the engine's state.
  SetKey malformed_key;
  malformed_key.fabric = FabricId::require("fabric-test");
  malformed_key.name_space = MultipathNamespace::require("ns-test");
  const FabricOutcome outcome =
      fixture.engine().create_set(fixture.context(), malformed_key, SetOptions{});
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::MALFORMED_REQUEST);
}

MPF_TEST(adversarial_zero_sentinels_are_rejected) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("zero-sentinel", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("zero-path", 1).succeeded());

  // A zero Path Authority generation can never be constructed, and the engine
  // refuses an unset one rather than treating it as a wildcard.
  MPF_CHECK(!PathAuthorityGeneration::from_value(0).has_value());
  const FabricOutcome outcome =
      fixture.engine().add_member(fixture.context(), set_id, PathId::require("zero-path"),
                                  PathAuthorityGeneration{});
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::MALFORMED_REQUEST);

  const FabricOutcome null_set =
      fixture.engine().publish_set(fixture.context(), MultipathSetId{});
  MPF_CHECK(!null_set.succeeded());
  MPF_CHECK_EQ(null_set.code, OutcomeCode::MALFORMED_REQUEST);
}

MPF_TEST(adversarial_duplicate_keys_and_identities_are_refused) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId first = fixture.create_set("duplicate-key", 1);
  MPF_REQUIRE(first.valid());
  const MultipathSetId second = fixture.create_set("duplicate-key", 1);
  MPF_CHECK(!second.valid());
  MPF_CHECK_EQ(fixture.engine().set_count(), std::size_t{1});
  // The semantic key resolves to exactly the set that owns it.
  SetKey key;
  key.fabric = FabricId::require("fabric-test");
  key.name_space = MultipathNamespace::require("ns-test");
  key.name = MultipathSetName::require("duplicate-key");
  const auto resolved = fixture.engine().find_set_by_key(key);
  MPF_REQUIRE(resolved.has_value());
  MPF_CHECK_EQ(resolved->view(), first.view());
}

MPF_TEST(adversarial_generation_exhaustion_is_structured) {
  // Drive a set generation to its maximum and prove the next mutation is
  // refused with GENERATION_OVERFLOW instead of wrapping.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("overflow-set", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto record = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(record.has_value());

  // The public API has no way to force a generation, so exhaustion is proved on
  // the checked counter itself and through the engine's own arithmetic.
  const auto maximum = MultipathSetGeneration::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum.has_value());
  MPF_CHECK(!maximum->next().has_value());
  const auto maximum_member = MultipathMemberGeneration::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum_member.has_value());
  MPF_CHECK(!maximum_member->next().has_value());
  const auto maximum_epoch = CoordinatorEpoch::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum_epoch.has_value());
  MPF_CHECK(!maximum_epoch->next().has_value());
  const auto maximum_membership = MembershipGeneration::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum_membership.has_value());
  MPF_CHECK(!maximum_membership->next().has_value());
  const auto maximum_authority = MultipathAuthorityGeneration::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum_authority.has_value());
  MPF_CHECK(!maximum_authority->next().has_value());

  // Threshold arithmetic near the limit does not overflow.
  MPF_CHECK(fixture.engine()
                .set_minimum_usable_members(fixture.context(), set_id, UINT64_MAX)
                .code == OutcomeCode::INVALID_THRESHOLD);
}

MPF_TEST(adversarial_threshold_above_member_count_is_refused) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("threshold", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const FabricOutcome outcome =
      fixture.engine().set_minimum_usable_members(fixture.context(), set_id, 1ULL << 40);
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::INVALID_THRESHOLD);
  MPF_CHECK_EQ(outcome.stage, RejectionStage::SEMANTIC);
  const MultipathSetId created = fixture.create_set("threshold-create", 1ULL << 40);
  MPF_CHECK(!created.valid());
}

MPF_TEST(adversarial_oversized_and_malformed_requests_are_refused) {
  mpf_test::FabricFixture fixture;
  // A batch larger than max_batch_size.
  Limits limits;
  limits.max_batch_size = 4;
  FabricConfig config;
  config.limits = limits;
  FabricEngine engine(config);
  AuthorityScope scope;
  scope.fabric = FabricId::require("fabric-test");
  scope.name_space = MultipathNamespace::require("ns-test");
  MPF_REQUIRE(engine
                  .register_publisher(PublisherId::require("batch-publisher"),
                                      WorkerBootId::require("batch-boot"), scope,
                                      SessionId::require("batch-session"))
                  .succeeded());
  MutationContext context;
  context.epoch = engine.epoch();
  context.publisher = PublisherId::require("batch-publisher");
  context.worker_boot = WorkerBootId::require("batch-boot");
  context.session = SessionId::require("batch-session");
  context.attempt = MutationAttemptId::require("batch-attempt");
  SetKey key;
  key.fabric = scope.fabric;
  key.name_space = scope.name_space;
  key.name = MultipathSetName::require("batch-set");
  const FabricOutcome created = engine.create_set(context, key, SetOptions{});
  MPF_REQUIRE(created.succeeded());
  std::vector<MemberRequest> batch(5);
  for (auto& member : batch) {
    member.path_id = PathId::require("batch-path");
    member.authority_generation = PathAuthorityGeneration::require(1);
  }
  const FabricOutcome rejected = engine.add_members(context, *created.set_id, batch);
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
  // An empty batch is malformed rather than silently accepted.
  MPF_CHECK_EQ(engine.add_members(context, *created.set_id, {}).code,
               OutcomeCode::MALFORMED_REQUEST);
  static_cast<void>(fixture);
}

MPF_TEST(adversarial_long_text_is_bounded) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("long-text", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const std::string huge(4096, 'x');
  MPF_CHECK_EQ(fixture.engine().retire_set(fixture.context(), set_id, huge).code,
               OutcomeCode::MALFORMED_REQUEST);
  MPF_CHECK_EQ(fixture.engine().withdraw_set(fixture.context(), set_id, huge).code,
               OutcomeCode::MALFORMED_REQUEST);
  MPF_CHECK_EQ(fixture.engine()
                   .revoke_set(fixture.context(), set_id, RevocationReason::SECURITY, huge)
                   .code,
               OutcomeCode::MALFORMED_REQUEST);
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
}

MPF_TEST(adversarial_frame_flood_is_bounded) {
  // Every structurally invalid frame is refused and no payload buffer larger
  // than the configured bound is ever produced.
  Limits limits;
  limits.max_frame_bytes = 128;
  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t length = 0;
  for (std::uint32_t declared = 0; declared < 4096; declared += 37) {
    std::vector<std::uint8_t> header(wire::frame_header_size);
    detail::ByteWriter writer(wire::frame_header_size);
    writer.u32(wire::frame_magic);
    writer.u16(wire_protocol_version);
    writer.u16(static_cast<std::uint16_t>(wire::MessageId::CREATE_SET));
    writer.u32(declared);
    writer.u32(0);
    std::copy(writer.buffer().begin(), writer.buffer().end(), header.begin());
    const FabricOutcome outcome = wire::decode_header(header.data(), header.size(), limits.max_frame_bytes, id,
                                                      length);
    if (declared <= limits.max_frame_bytes) {
      MPF_CHECK(outcome.succeeded());
    } else {
      MPF_CHECK(!outcome.succeeded());
      MPF_CHECK_EQ(outcome.code, OutcomeCode::RESOURCE_LIMIT);
    }
  }
}

MPF_TEST(adversarial_reconnect_style_repeated_registration_is_stable) {
  mpf_test::FabricFixture fixture;
  for (int round = 0; round < 200; ++round) {
    const WorkerBootId boot = WorkerBootId::require("reconnect-boot-" + std::to_string(round));
    const SessionId session = SessionId::require("reconnect-session-" + std::to_string(round));
    const FabricOutcome outcome = fixture.engine().register_publisher(
        fixture.publisher(), boot, fixture.scope(), session);
    MPF_CHECK(outcome.succeeded());
    MPF_CHECK(fixture.engine().unregister_publisher(fixture.publisher(), boot).succeeded());
  }
  const AuthorityDescription description = fixture.engine().describe_authority();
  MPF_CHECK_EQ(description.registrations.size(), std::size_t{1});
  MPF_CHECK(description.authority_generation.value() > 1);
}

MPF_TEST(adversarial_integrity_report_detects_nothing_after_heavy_use) {
  mpf_test::FabricFixture fixture(4242);
  std::vector<MultipathSetId> sets;
  for (int index = 0; index < 8; ++index) {
    const MultipathSetId set_id =
        fixture.build_set("heavy-" + std::to_string(index), 1, 3);
    MPF_REQUIRE(set_id.valid());
    sets.push_back(set_id);
  }
  for (int round = 0; round < 60; ++round) {
    const std::string path = "heavy-path-" + std::to_string(round % 12);
    MPF_CHECK(fixture
                  .declare(path, 1 + static_cast<std::uint64_t>(round % 3),
                           (round % 2 == 0) ? PathAuthorityState::REJECTED
                                            : PathAuthorityState::AUTHORIZED)
                  .succeeded());
    const FabricIntegrityReport report = fixture.engine().check_integrity();
    MPF_CHECK_MSG(report.consistent, report.render());
  }
  for (const auto& set_id : sets) {
    MPF_CHECK(fixture.revalidate(set_id).succeeded());
  }
  const FabricIntegrityReport report = fixture.engine().check_integrity();
  MPF_CHECK_MSG(report.consistent, report.render());
  MPF_CHECK_EQ(report.set_count, std::size_t{8});
  MPF_CHECK_EQ(report.member_count, std::size_t{24});
  for (const auto& set_id : sets) {
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    MPF_CHECK(snapshot->usable_member_count <= snapshot->member_count);
  }
}

MPF_TEST(adversarial_diff_and_history_are_deterministic_under_churn) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("churn", 1, 2);
  MPF_REQUIRE(set_id.valid());
  std::string previous_digest;
  for (int round = 0; round < 10; ++round) {
    const std::string path = "churn-" + std::to_string(round);
    MPF_REQUIRE(fixture.declare(path, 1).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, path, 1).succeeded());
    const auto diff = fixture.engine().diff_last_two(set_id);
    MPF_REQUIRE(diff.has_value());
    MPF_CHECK(!diff->identical);
    // Entries are in the fixed (kind, subject, before, after) order.
    for (std::size_t index = 1; index < diff->entries.size(); ++index) {
      MPF_CHECK(diff->entries[index - 1] < diff->entries[index] ||
                diff->entries[index - 1] == diff->entries[index]);
    }
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    MPF_CHECK(snapshot->digest.to_hex() != previous_digest);
    previous_digest = snapshot->digest.to_hex();
  }
}