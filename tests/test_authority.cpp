#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

MPF_TEST(context_missing_identity_is_rejected_first) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("identity", 1, 1);
  MPF_REQUIRE(set_id.valid());

  MutationContext blank;
  const FabricOutcome outcome = fixture.engine().add_member(
      blank, set_id, PathId::require("identity-extra"), PathAuthorityGeneration::require(1));
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::UNAUTHORIZED_CALLER);
  MPF_CHECK_EQ(outcome.stage, RejectionStage::CALLER_IDENTITY);
}

MPF_TEST(stale_epoch_is_rejected_before_worker_and_scope) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("epoch", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("epoch-extra", 1).succeeded());

  MutationContext context = fixture.context();
  context.epoch = CoordinatorEpoch::require(fixture.engine().epoch().value() + 5);
  const FabricOutcome outcome =
      fixture.engine().add_member(context, set_id, PathId::require("epoch-extra"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::STALE_EPOCH);
  MPF_CHECK_EQ(outcome.stage, RejectionStage::EPOCH);
}

MPF_TEST(unknown_publisher_and_fenced_worker_are_rejected) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("fencing", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("fencing-extra", 1).succeeded());

  MutationContext unknown = fixture.context();
  unknown.worker_boot = WorkerBootId::require("boot-never-registered");
  const FabricOutcome not_registered =
      fixture.engine().add_member(unknown, set_id, PathId::require("fencing-extra"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK_EQ(not_registered.code, OutcomeCode::UNKNOWN_PUBLISHER);
  MPF_CHECK_EQ(not_registered.stage, RejectionStage::WORKER_AUTHORITY);

  // Recording a durable membership fact before fencing gives the fence meaning.
  MPF_REQUIRE(fixture
                  .engine()
                  .add_member(fixture.context(), set_id, PathId::require("fencing-extra"),
                              PathAuthorityGeneration::require(1))
                  .succeeded());
  const FabricOutcome fenced =
      fixture.engine().fence_worker(fixture.publisher(), fixture.boot(), "TEST_FENCE");
  MPF_CHECK(fenced.succeeded());
  MPF_CHECK_EQ(fenced.code, OutcomeCode::WORKER_FENCED);
  MPF_CHECK(fixture.engine().is_fenced(fixture.publisher(), fixture.boot()));

  // The fenced boot can never mutate again, even with a fresh attempt id.
  const FabricOutcome after_fence =
      fixture.engine().add_member(fixture.context(), set_id, PathId::require("fencing-extra-2"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK(!after_fence.succeeded());
  MPF_CHECK_EQ(after_fence.code, OutcomeCode::STALE_WORKER);

  // Fencing the same boot twice is idempotent.
  const FabricOutcome again =
      fixture.engine().fence_worker(fixture.publisher(), fixture.boot(), "TEST_FENCE");
  MPF_CHECK(again.succeeded());
  MPF_CHECK_EQ(again.code, OutcomeCode::IDEMPOTENT);

  // A fresh boot cannot simply re-register the fenced boot identity; but a brand
  // new boot can, and it receives a fresh authority generation.
  const WorkerBootId fresh_boot = WorkerBootId::require("boot-test-2");
  const FabricOutcome registered =
      fixture.engine().register_publisher(fixture.publisher(), fresh_boot, fixture.scope(),
                                          SessionId::require("session-test-2"));
  MPF_CHECK(registered.succeeded());
  MPF_CHECK_EQ(registered.code, OutcomeCode::PUBLISHER_REGISTERED);
  MPF_CHECK(!fixture.engine().is_fenced(fixture.publisher(), fresh_boot));

  MutationContext fresh;
  fresh.epoch = fixture.engine().epoch();
  fresh.publisher = fixture.publisher();
  fresh.worker_boot = fresh_boot;
  fresh.session = SessionId::require("session-test-2");
  fresh.attempt = MutationAttemptId::require("fencing-fresh-declare");
  PathAuthorityView fresh_view;
  fresh_view.path = PathId::require("fencing-extra-2");
  fresh_view.generation = PathAuthorityGeneration::require(1);
  fresh_view.state = PathAuthorityState::AUTHORIZED;
  MPF_REQUIRE(fixture.engine().declare_path_authority(fresh, fresh_view).succeeded());
  fresh.attempt = MutationAttemptId::require("fencing-fresh-add");
  const FabricOutcome accepted =
      fixture.engine().add_member(fresh, set_id, PathId::require("fencing-extra-2"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK(accepted.succeeded());
}

MPF_TEST(authority_scope_defaults_to_deny_and_is_enforced) {
  FabricEngine engine;
  const PublisherId publisher = PublisherId::require("scoped-publisher");
  const WorkerBootId boot = WorkerBootId::require("scoped-boot");
  const SessionId session = SessionId::require("scoped-session");

  // An incomplete scope is refused outright.
  AuthorityScope incomplete;
  incomplete.fabric = FabricId::require("fabric-a");
  const FabricOutcome refused = engine.register_publisher(publisher, boot, incomplete, session);
  MPF_CHECK(!refused.succeeded());
  MPF_CHECK_EQ(refused.code, OutcomeCode::UNAUTHORIZED_SCOPE);

  AuthorityScope scope;
  scope.fabric = FabricId::require("fabric-a");
  scope.name_space = MultipathNamespace::require("ns-a");
  MPF_REQUIRE(engine.register_publisher(publisher, boot, scope, session).succeeded());

  std::uint64_t attempts = 0;
  const auto context = [&]() {
    MutationContext value;
    value.epoch = engine.epoch();
    value.publisher = publisher;
    value.worker_boot = boot;
    value.session = session;
    value.attempt = MutationAttemptId::require("scoped-attempt-" + std::to_string(++attempts));
    return value;
  };

  SetKey inside;
  inside.fabric = scope.fabric;
  inside.name_space = scope.name_space;
  inside.name = MultipathSetName::require("inside");
  SetOptions options;
  options.minimum_usable_members = 0;
  const FabricOutcome created = engine.create_set(context(), inside, options);
  MPF_CHECK(created.succeeded());

  // A different namespace is outside the scope.
  SetKey outside;
  outside.fabric = scope.fabric;
  outside.name_space = MultipathNamespace::require("ns-b");
  outside.name = MultipathSetName::require("outside");
  const FabricOutcome cross_namespace = engine.create_set(context(), outside, options);
  MPF_CHECK(!cross_namespace.succeeded());
  MPF_CHECK_EQ(cross_namespace.code, OutcomeCode::UNAUTHORIZED_SCOPE);
  MPF_CHECK_EQ(cross_namespace.stage, RejectionStage::SCOPE);

  // A different fabric is outside the scope.
  SetKey other_fabric;
  other_fabric.fabric = FabricId::require("fabric-b");
  other_fabric.name_space = scope.name_space;
  other_fabric.name = MultipathSetName::require("other-fabric");
  MPF_CHECK_EQ(engine.create_set(context(), other_fabric, options).code,
               OutcomeCode::UNAUTHORIZED_SCOPE);

  // A set-restricted scope cannot create a new set at all.
  const WorkerBootId restricted_boot = WorkerBootId::require("restricted-boot");
  AuthorityScope restricted;
  restricted.fabric = scope.fabric;
  restricted.name_space = scope.name_space;
  restricted.set_ids.push_back(*created.set_id);
  MPF_REQUIRE(engine
                  .register_publisher(publisher, restricted_boot, restricted,
                                      SessionId::require("restricted-session"))
                  .succeeded());
  MutationContext restricted_context;
  restricted_context.epoch = engine.epoch();
  restricted_context.publisher = publisher;
  restricted_context.worker_boot = restricted_boot;
  restricted_context.session = SessionId::require("restricted-session");
  restricted_context.attempt = MutationAttemptId::require("restricted-attempt-1");
  SetKey another;
  another.fabric = scope.fabric;
  another.name_space = scope.name_space;
  another.name = MultipathSetName::require("another");
  const FabricOutcome restricted_create = engine.create_set(restricted_context, another, options);
  MPF_CHECK(!restricted_create.succeeded());
  MPF_CHECK_EQ(restricted_create.code, OutcomeCode::UNAUTHORIZED_SCOPE);

  // The restricted scope may mutate the listed set but not an unlisted one.
  SetKey second;
  second.fabric = scope.fabric;
  second.name_space = scope.name_space;
  second.name = MultipathSetName::require("second");
  const FabricOutcome second_created = engine.create_set(context(), second, options);
  MPF_REQUIRE(second_created.succeeded());

  MutationContext second_context = restricted_context;
  second_context.attempt = MutationAttemptId::require("restricted-attempt-2");
  const FabricOutcome listed =
      engine.publish_set(second_context, *created.set_id);
  MPF_CHECK(listed.succeeded());
  MutationContext other_context = restricted_context;
  other_context.attempt = MutationAttemptId::require("restricted-attempt-3");
  const FabricOutcome unlisted = engine.publish_set(other_context, *second_created.set_id);
  MPF_CHECK(!unlisted.succeeded());
  MPF_CHECK_EQ(unlisted.code, OutcomeCode::UNAUTHORIZED_SCOPE);
}

MPF_TEST(attempt_identity_detects_replay_and_conflict) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("attempts", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("attempts-a", 1).succeeded());
  MPF_REQUIRE(fixture.declare("attempts-b", 1).succeeded());

  MutationContext context = fixture.context();
  context.expected_set_generation = fixture.engine().snapshot(set_id)->generation;
  const FabricOutcome first = fixture.engine().add_member(
      context, set_id, PathId::require("attempts-a"), PathAuthorityGeneration::require(1));
  MPF_REQUIRE(first.succeeded());
  const auto after_first = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after_first.has_value());

  // Exact replay with the same attempt id and the same semantic request returns
  // IDEMPOTENT, advances no generation and changes no digest.
  const FabricOutcome replay = fixture.engine().add_member(
      context, set_id, PathId::require("attempts-a"), PathAuthorityGeneration::require(1));
  MPF_CHECK(replay.succeeded());
  MPF_CHECK_EQ(replay.code, OutcomeCode::IDEMPOTENT);
  const auto after_replay = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after_replay.has_value());
  MPF_CHECK_EQ(after_replay->generation.value(), after_first->generation.value());
  MPF_CHECK_EQ(after_replay->digest.to_hex(), after_first->digest.to_hex());

  // Reusing the attempt id for a different semantic request is a conflict.
  const FabricOutcome conflict = fixture.engine().add_member(
      context, set_id, PathId::require("attempts-b"), PathAuthorityGeneration::require(1));
  MPF_CHECK(!conflict.succeeded());
  MPF_CHECK_EQ(conflict.code, OutcomeCode::ATTEMPT_CONFLICT);
  MPF_CHECK_EQ(conflict.stage, RejectionStage::ATTEMPT);
}

MPF_TEST(stale_authority_outranks_attempt_replay) {
  // A replay is only recognised after every authority check has passed. A stale
  // epoch therefore rejects even a request whose attempt id is known.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("stale-replay", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("stale-replay-a", 1).succeeded());
  MutationContext context = fixture.context();
  const FabricOutcome first = fixture.engine().add_member(
      context, set_id, PathId::require("stale-replay-a"), PathAuthorityGeneration::require(1));
  MPF_REQUIRE(first.succeeded());

  MutationContext stale = context;
  stale.epoch = CoordinatorEpoch::require(fixture.engine().epoch().value() + 1);
  const FabricOutcome rejected = fixture.engine().add_member(
      stale, set_id, PathId::require("stale-replay-a"), PathAuthorityGeneration::require(1));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::STALE_EPOCH);

  // A fenced worker replay is rejected the same way.
  MPF_REQUIRE(fixture.engine().fence_worker(fixture.publisher(), fixture.boot(), "TEST").succeeded());
  MutationContext fenced = context;
  const FabricOutcome after_fence = fixture.engine().add_member(
      fenced, set_id, PathId::require("stale-replay-a"), PathAuthorityGeneration::require(1));
  MPF_CHECK(!after_fence.succeeded());
  MPF_CHECK_EQ(after_fence.code, OutcomeCode::STALE_WORKER);
}

MPF_TEST(rejection_precedence_is_fixed_and_ordered) {
  const std::vector<RejectionStage> precedence = rejection_precedence();
  MPF_REQUIRE(precedence.size() == 12);
  MPF_CHECK_EQ(precedence[0], RejectionStage::DECODE);
  MPF_CHECK_EQ(precedence[1], RejectionStage::CALLER_IDENTITY);
  MPF_CHECK_EQ(precedence[2], RejectionStage::EPOCH);
  MPF_CHECK_EQ(precedence[3], RejectionStage::WORKER_AUTHORITY);
  MPF_CHECK_EQ(precedence[4], RejectionStage::SCOPE);
  MPF_CHECK_EQ(precedence[5], RejectionStage::ATTEMPT);
  MPF_CHECK_EQ(precedence[6], RejectionStage::SET_STATE);
  MPF_CHECK_EQ(precedence[7], RejectionStage::GENERATION);
  MPF_CHECK_EQ(precedence[8], RejectionStage::PATH_AUTHORITY);
  MPF_CHECK_EQ(precedence[9], RejectionStage::RESOURCE_LIMIT);
  MPF_CHECK_EQ(precedence[10], RejectionStage::SEMANTIC);
  MPF_CHECK_EQ(precedence[11], RejectionStage::COMMIT);
  for (std::size_t index = 0; index < precedence.size(); ++index) {
    MPF_CHECK_EQ(static_cast<std::uint8_t>(precedence[index]),
                 static_cast<std::uint8_t>(index + 1));
  }

  // Multi-failure input: an anonymous caller with a stale epoch, an unknown
  // boot, a blank attempt and a malformed set identity resolves at the earliest
  // stage, which is CALLER_IDENTITY.
  mpf_test::FabricFixture fixture;
  MutationContext blank;
  blank.epoch = CoordinatorEpoch::require(fixture.engine().epoch().value() + 3);
  blank.publisher = PublisherId::require("never-registered");
  const FabricOutcome outcome =
      fixture.engine().add_member(blank, MultipathSetId::require("no-such-set"),
                                  PathId::require("no-such-path"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK_EQ(outcome.code, OutcomeCode::UNAUTHORIZED_CALLER);
  MPF_CHECK_EQ(outcome.stage, RejectionStage::CALLER_IDENTITY);

  // With a full caller identity but a stale epoch and an unknown boot the epoch
  // stage wins.
  MutationContext stale = fixture.context();
  stale.epoch = CoordinatorEpoch::require(fixture.engine().epoch().value() + 3);
  stale.worker_boot = WorkerBootId::require("never-registered-either");
  stale.publisher = PublisherId::require("never-registered-either");
  const FabricOutcome epoch_first =
      fixture.engine().add_member(stale, MultipathSetId::require("no-such-set"),
                                  PathId::require("no-such-path"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK_EQ(epoch_first.code, OutcomeCode::STALE_EPOCH);
}

MPF_TEST(explain_rejection_reports_stage_and_precedence) {
  const FabricOutcome outcome =
      make_rejection(OutcomeCode::STALE_EPOCH, "epoch 1 is not the governing epoch 2");
  const RejectionExplanation explanation = explain_rejection(outcome);
  MPF_CHECK_EQ(explanation.code, OutcomeCode::STALE_EPOCH);
  MPF_CHECK_EQ(explanation.stage, RejectionStage::EPOCH);
  MPF_CHECK_EQ(explanation.precedence, std::uint8_t{3});
  MPF_CHECK(!explanation.guidance.empty());
  const std::string rendered = explanation.render();
  MPF_CHECK(rendered.find("STALE_EPOCH") != std::string::npos);
  MPF_CHECK(rendered.find("precedence=3") != std::string::npos);
}

MPF_TEST(epoch_advance_fences_every_registration_and_preserves_membership) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("epoch-advance", 2, 3);
  MPF_REQUIRE(set_id.valid());
  auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());
  MPF_CHECK_EQ(before->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(before->currentness, SetCurrentness::CURRENT);

  const CoordinatorEpoch previous = fixture.engine().epoch();
  const FabricOutcome advanced = fixture.engine().advance_epoch(
      fixture.publisher(), fixture.boot(), fixture.session(), previous,
      MutationAttemptId::require("epoch-advance-attempt"));
  MPF_CHECK(advanced.succeeded());
  MPF_CHECK_EQ(advanced.code, OutcomeCode::EPOCH_ADVANCED);

  const CoordinatorEpoch next = fixture.engine().epoch();
  MPF_CHECK_EQ(next.value(), previous.value() + 1);
  MPF_CHECK(fixture.engine().is_fenced(fixture.publisher(), fixture.boot()));

  // Durable membership survives; live currentness does not.
  auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->member_count, before->member_count);
  MPF_CHECK_EQ(after->usable_member_count, before->usable_member_count);
  MPF_CHECK_EQ(after->currentness, SetCurrentness::REVALIDATION_REQUIRED);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::REVALIDATION_REQUIRED);
  MPF_CHECK_EQ(after->governing_epoch.value(), next.value());

  // Old epoch traffic is rejected.
  MutationContext old_epoch = fixture.context();
  old_epoch.epoch = previous;
  const FabricOutcome rejected = fixture.engine().revalidate_set(old_epoch, set_id);
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::STALE_EPOCH);

  // A fresh boot registers again and revalidation restores live currentness.
  const WorkerBootId fresh_boot = WorkerBootId::require("boot-epoch-2");
  const SessionId fresh_session = SessionId::require("session-epoch-2");
  MPF_REQUIRE(fixture.engine()
                  .register_publisher(fixture.publisher(), fresh_boot, fixture.scope(),
                                      fresh_session)
                  .succeeded());
  MutationContext fresh;
  fresh.epoch = next;
  fresh.publisher = fixture.publisher();
  fresh.worker_boot = fresh_boot;
  fresh.session = fresh_session;
  fresh.attempt = MutationAttemptId::require("epoch-advance-revalidate");
  const FabricOutcome revalidated = fixture.engine().revalidate_set(fresh, set_id);
  MPF_CHECK(revalidated.succeeded());
  after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->currentness, SetCurrentness::CURRENT);
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::READY);
}

MPF_TEST(authority_description_reports_registrations_and_fences) {
  mpf_test::FabricFixture fixture;
  const AuthorityDescription description = fixture.engine().describe_authority();
  MPF_CHECK_EQ(description.registrations.size(), std::size_t{1});
  MPF_CHECK_EQ(description.epoch.value(), fixture.engine().epoch().value());
  const std::string rendered = description.render();
  MPF_CHECK(rendered.find("publisher-test") != std::string::npos);
  MPF_REQUIRE(fixture.engine().fence_worker(fixture.publisher(), fixture.boot(), "TEST").succeeded());
  const AuthorityDescription after = fixture.engine().describe_authority();
  MPF_CHECK_EQ(after.registrations.size(), std::size_t{0});
  MPF_CHECK_EQ(after.fence_records.size(), std::size_t{1});
  MPF_CHECK(after.render().find("TEST") != std::string::npos);
}
