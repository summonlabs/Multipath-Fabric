#include <atomic>
#include <barrier>
#include <string>
#include <thread>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

// ---------------------------------------------------------------------------
// Deterministic interleaved races
//
// These force an exact ordering through the public API rather than through
// threads, so the expected outcome is pinned exactly instead of being one of
// several legal outcomes.
// ---------------------------------------------------------------------------

MPF_TEST(race_add_then_remove_and_remove_then_add_are_both_legal) {
  // Order A: add the member, then remove it.
  {
    mpf_test::FabricFixture fixture;
    const MultipathSetId set_id = fixture.build_set("order-a", 1, 1);
    MPF_REQUIRE(set_id.valid());
    MPF_REQUIRE(fixture.declare("order-a-extra", 1).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, "order-a-extra", 1).succeeded());
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    MPF_CHECK_EQ(snapshot->member_count, std::size_t{2});
    const MultipathMemberId member = snapshot->find_member(PathId::require("order-a-extra"))->id;
    const FabricOutcome removed =
        fixture.engine().remove_member(fixture.context(), set_id, member, "race");
    MPF_CHECK(removed.succeeded());
    MPF_CHECK_EQ(fixture.engine().snapshot(set_id)->member_count, std::size_t{1});
  }
  // Order B: remove first, then a late add for the very same path re-admits it.
  {
    mpf_test::FabricFixture fixture;
    const MultipathSetId set_id = fixture.build_set("order-b", 1, 1);
    MPF_REQUIRE(set_id.valid());
    MPF_REQUIRE(fixture.declare("order-b-extra", 1).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, "order-b-extra", 1).succeeded());
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    const MultipathMemberId member = snapshot->find_member(PathId::require("order-b-extra"))->id;
    MPF_REQUIRE(fixture.engine().remove_member(fixture.context(), set_id, member, "race").succeeded());
    const FabricOutcome late = fixture.add_member(set_id, "order-b-extra", 1);
    MPF_CHECK(late.succeeded());
    MPF_CHECK_EQ(fixture.engine().snapshot(set_id)->member_count, std::size_t{2});
  }
}

MPF_TEST(race_membership_add_versus_set_retirement) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("add-vs-retire", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("add-vs-retire-extra", 1).succeeded());
  MPF_REQUIRE(fixture.engine().retire_set(fixture.context(), set_id, "race").succeeded());
  const auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());

  // The late membership completion cannot reactivate the retired set.
  const FabricOutcome late = fixture.add_member(set_id, "add-vs-retire-extra", 1);
  MPF_CHECK(!late.succeeded());
  MPF_CHECK_EQ(late.code, OutcomeCode::RETIRED);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->digest.to_hex(), before->digest.to_hex());
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::RETIRED);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::RETIRED);
}

MPF_TEST(race_revalidation_versus_path_invalidation) {
  // The invalidation wins: the member cannot report the superseded generation.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("reval-vs-invalidate", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  MPF_REQUIRE(fixture.declare("reval-path", 1).succeeded());
  MPF_REQUIRE(fixture.add_member(set_id, "reval-path", 1).succeeded());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member = snapshot->members.front().id;

  const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member, RevalidationAttemptId::require("race-1"));
  MPF_REQUIRE(begun.outcome.succeeded());
  MPF_REQUIRE(fixture.declare("reval-path", 2, PathAuthorityState::AUTHORIZED).succeeded());

  PathAuthorityView stale;
  stale.path = PathId::require("reval-path");
  stale.generation = PathAuthorityGeneration::require(1);
  stale.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome completion =
      fixture.engine().complete_member_revalidation(fixture.context(), *begun.ticket, stale);
  MPF_CHECK(!completion.succeeded());
  MPF_CHECK_EQ(completion.code, OutcomeCode::STALE_REVALIDATION);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->find_member(member)->bound_authority_generation.value(), std::uint64_t{1});
  MPF_CHECK(!after->find_member(member)->usable);
}

MPF_TEST(race_revalidation_versus_epoch_advance) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("reval-vs-epoch", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member = snapshot->members.front().id;
  const PathId path = snapshot->members.front().path_id;

  const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member, RevalidationAttemptId::require("race-epoch"));
  MPF_REQUIRE(begun.outcome.succeeded());
  MPF_REQUIRE(fixture.engine()
                  .advance_epoch(fixture.publisher(), fixture.boot(), fixture.session(),
                                 fixture.engine().epoch(),
                                 MutationAttemptId::require("race-epoch-advance"))
                  .succeeded());

  PathAuthorityView view;
  view.path = path;
  view.generation = PathAuthorityGeneration::require(1);
  view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome completion =
      fixture.engine().complete_member_revalidation(fixture.context(), *begun.ticket, view);
  MPF_CHECK(!completion.succeeded());
  MPF_CHECK(completion.code == OutcomeCode::STALE_EPOCH ||
            completion.code == OutcomeCode::STALE_REVALIDATION ||
            completion.code == OutcomeCode::STALE_WORKER);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->currentness, SetCurrentness::REVALIDATION_REQUIRED);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::REVALIDATION_REQUIRED);
}

MPF_TEST(race_revocation_versus_member_add) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("revoke-vs-add", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("revoke-vs-add-extra", 1).succeeded());
  MPF_REQUIRE(fixture.engine()
                  .revoke_set(fixture.context(), set_id, RevocationReason::POLICY_VIOLATION, "race")
                  .succeeded());
  const FabricOutcome late = fixture.add_member(set_id, "revoke-vs-add-extra", 1);
  MPF_CHECK(!late.succeeded());
  MPF_CHECK_EQ(late.code, OutcomeCode::REVOKED);
  MPF_CHECK_EQ(fixture.engine().snapshot(set_id)->lifecycle, SetLifecycle::REVOKED);
}

MPF_TEST(race_worker_fencing_versus_commit) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("fence-vs-commit", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("fence-vs-commit-extra", 1).succeeded());

  MutationContext context = fixture.context();
  const FabricOutcome committed =
      fixture.engine().add_member(context, set_id, PathId::require("fence-vs-commit-extra"),
                                  PathAuthorityGeneration::require(1));
  MPF_REQUIRE(committed.succeeded());

  // Fencing after the commit stops all further work from that boot.
  MPF_REQUIRE(fixture.engine().fence_worker(fixture.publisher(), fixture.boot(), "race").succeeded());
  const FabricOutcome after_fence =
      fixture.engine().add_member(context, set_id, PathId::require("fence-vs-commit-extra"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK(!after_fence.succeeded());
  MPF_CHECK_EQ(after_fence.code, OutcomeCode::STALE_WORKER);
  // The committed membership survives the fence.
  MPF_CHECK_EQ(fixture.engine().snapshot(set_id)->member_count, std::size_t{2});
}

MPF_TEST(race_duplicate_expected_generation_mutations) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("duplicate-generation", 1, 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("duplicate-generation-a", 1).succeeded());
  MPF_REQUIRE(fixture.declare("duplicate-generation-b", 1).succeeded());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());

  MutationContext first = fixture.context();
  first.expected_set_generation = snapshot->generation;
  MutationContext second = fixture.context();
  second.expected_set_generation = snapshot->generation;

  MPF_CHECK(fixture.engine()
                .add_member(first, set_id, PathId::require("duplicate-generation-a"),
                            PathAuthorityGeneration::require(1))
                .succeeded());
  // The second mutation carried the same expectation and is rejected instead of
  // silently applying on top of the advanced generation.
  const FabricOutcome rejected =
      fixture.engine().add_member(second, set_id, PathId::require("duplicate-generation-b"),
                                  PathAuthorityGeneration::require(1));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::STALE_SET_GENERATION);
  MPF_CHECK_EQ(rejected.stage, RejectionStage::GENERATION);
  MPF_CHECK_EQ(fixture.engine().snapshot(set_id)->member_count, std::size_t{2});
}

MPF_TEST(race_stale_completion_versus_fresh_completion) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("two-completions", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member = snapshot->members.front().id;
  const PathId path = snapshot->members.front().path_id;

  const RevalidationBegin stale_begin = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member, RevalidationAttemptId::require("stale-completion"));
  const RevalidationBegin fresh_begin = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member, RevalidationAttemptId::require("fresh-completion"));
  MPF_REQUIRE(stale_begin.outcome.succeeded());
  MPF_REQUIRE(fresh_begin.outcome.succeeded());

  // Path Authority advances; the fresh completion uses the new view and commits.
  MPF_REQUIRE(fixture.declare("two-completions-0", 2, PathAuthorityState::AUTHORIZED).succeeded());
  PathAuthorityView fresh_view;
  fresh_view.path = path;
  fresh_view.generation = PathAuthorityGeneration::require(2);
  fresh_view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome fresh = fixture.engine().complete_member_revalidation(
      fixture.context(), *fresh_begin.ticket, fresh_view);
  MPF_CHECK(fresh.succeeded());

  // The stale completion arrives afterwards and is refused.
  PathAuthorityView stale_view;
  stale_view.path = path;
  stale_view.generation = PathAuthorityGeneration::require(1);
  stale_view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome stale = fixture.engine().complete_member_revalidation(
      fixture.context(), *stale_begin.ticket, stale_view);
  MPF_CHECK(!stale.succeeded());
  MPF_CHECK_EQ(stale.code, OutcomeCode::STALE_REVALIDATION);

  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->find_member(member)->bound_authority_generation.value(), std::uint64_t{2});
  MPF_CHECK(after->find_member(member)->usable);
  MPF_CHECK_EQ(after->find_member(member)->pending_revalidations, std::uint32_t{0});
}

MPF_TEST(race_path_invalidation_storm_keeps_indexes_consistent) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("storm", 2, 5);
  MPF_REQUIRE(set_id.valid());
  for (int round = 0; round < 40; ++round) {
    const std::string path = "path-storm-" + std::to_string(round % 5);
    const std::uint64_t generation = 1 + static_cast<std::uint64_t>(round % 4);
    const auto state = (round % 2 == 0) ? PathAuthorityState::REJECTED
                                        : PathAuthorityState::AUTHORIZED;
    const FabricOutcome outcome = fixture.declare(path, generation, state);
    MPF_CHECK(outcome.succeeded());
    const FabricIntegrityReport report = fixture.engine().check_integrity();
    MPF_CHECK_MSG(report.consistent, report.render());
  }
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  // Exactly five members remain; none of them is duplicated.
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{5});
  MPF_CHECK(snapshot->usable_member_count <= 5);
}

// ---------------------------------------------------------------------------
// Barrier controlled multi-threaded races
// ---------------------------------------------------------------------------

MPF_TEST(race_barrier_revalidation_against_invalidation) {
  // Two threads meet at a barrier: one completes a member revalidation, the
  // other invalidates the same path. Whichever order wins, the final state must
  // never report the superseded generation as usable.
  for (int iteration = 0; iteration < 25; ++iteration) {
    mpf_test::FabricFixture fixture(static_cast<std::uint64_t>(iteration) + 1);
    const MultipathSetId set_id = fixture.create_set("barrier", 1);
    MPF_REQUIRE(set_id.valid());
    MPF_REQUIRE(fixture.publish(set_id).succeeded());
    MPF_REQUIRE(fixture.declare("barrier-path", 8).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, "barrier-path", 8).succeeded());
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    const MultipathMemberId member = snapshot->members.front().id;

    const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
        fixture.context(), set_id, member,
        RevalidationAttemptId::require("barrier-" + std::to_string(iteration)));
    MPF_REQUIRE(begun.outcome.succeeded());

    // Contexts are built before the threads start so that no two threads touch
    // the fixture's attempt counter.
    MutationContext revalidator_context = fixture.context();
    MutationContext invalidator_context = fixture.context();
    PathAuthorityView first_view;
    first_view.path = PathId::require("barrier-path");
    first_view.generation = PathAuthorityGeneration::require(8);
    first_view.state = PathAuthorityState::AUTHORIZED;
    PathAuthorityView second_view;
    second_view.path = PathId::require("barrier-path");
    second_view.generation = PathAuthorityGeneration::require(9);
    second_view.state = PathAuthorityState::AUTHORIZED;

    std::barrier gate(3);
    std::atomic<bool> invalidated{false};
    std::thread revalidator([&]() {
      gate.arrive_and_wait();
      const FabricOutcome outcome = fixture.engine().complete_member_revalidation(
          revalidator_context, *begun.ticket, first_view);
      // Either the completion commits before the invalidation, or it is refused
      // as stale. Nothing else is legal.
      MPF_CHECK(outcome.succeeded() || outcome.code == OutcomeCode::STALE_REVALIDATION);
    });
    std::thread invalidator([&]() {
      gate.arrive_and_wait();
      const FabricOutcome outcome =
          fixture.engine().declare_path_authority(invalidator_context, second_view);
      MPF_CHECK(outcome.succeeded());
      invalidated.store(true);
    });
    gate.arrive_and_wait();
    revalidator.join();
    invalidator.join();
    MPF_CHECK(invalidated.load());

    const auto after = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(after.has_value());
    const MemberSnapshot* final_member = after->find_member(member);
    MPF_REQUIRE(final_member != nullptr);
    // The member is either still bound to generation 8 and unusable, or rebound
    // to generation 9 and usable. Generation 8 is never usable.
    if (final_member->bound_authority_generation.value() == 8) {
      MPF_CHECK(!final_member->usable);
    } else {
      MPF_CHECK_EQ(final_member->bound_authority_generation.value(), std::uint64_t{9});
    }
    MPF_CHECK_EQ(final_member->pending_revalidations, std::uint32_t{0});
    const FabricIntegrityReport report = fixture.engine().check_integrity();
    MPF_CHECK(report.consistent);
  }
}

MPF_TEST(race_barrier_concurrent_queries_during_mutation) {
  // Readers take the shared lock while a writer mutates. Every observed snapshot
  // must be self consistent. The readers perform a FIXED number of observations
  // so the test does not depend on how fast the writer happens to be.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("concurrent", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  for (int index = 0; index < 8; ++index) {
    MPF_REQUIRE(fixture.declare("concurrent-" + std::to_string(index), 1).succeeded());
  }

  constexpr int kReaders = 4;
  constexpr int kObservationsPerReader = 250;
  std::barrier gate(kReaders + 1);
  std::atomic<std::uint64_t> inconsistent{0};
  std::vector<std::thread> readers;
  readers.reserve(kReaders);
  for (int index = 0; index < kReaders; ++index) {
    readers.emplace_back([&]() {
      gate.arrive_and_wait();
      for (int iteration = 0; iteration < kObservationsPerReader; ++iteration) {
        const auto snapshot = fixture.engine().snapshot(set_id);
        if (!snapshot.has_value()) {
          inconsistent.fetch_add(1);
          continue;
        }
        std::uint64_t usable = 0;
        for (const auto& member : snapshot->members) {
          if (member.usable) {
            ++usable;
          }
        }
        if (usable != snapshot->usable_member_count ||
            snapshot->usable_member_count > snapshot->member_count) {
          inconsistent.fetch_add(1);
        }
        if (snapshot->digest.to_hex() != snapshot->snapshot_id.str().substr(5)) {
          inconsistent.fetch_add(1);
        }
      }
    });
  }
  gate.arrive_and_wait();
  for (int index = 0; index < 8; ++index) {
    const std::string path = "concurrent-" + std::to_string(index);
    const FabricOutcome outcome = fixture.add_member(set_id, path, 1);
    MPF_CHECK_MSG(outcome.succeeded(), outcome.render());
  }
  for (auto& reader : readers) {
    reader.join();
  }
  MPF_CHECK_EQ(inconsistent.load(), std::uint64_t{0});
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->member_count, std::size_t{8});
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{8});
  const FabricIntegrityReport report = fixture.engine().check_integrity();
  MPF_CHECK_MSG(report.consistent, report.render());
}

MPF_TEST(race_barrier_persistence_during_mutation) {
  // Saving the durable store runs concurrently with membership mutation. Every
  // save must complete and the final store must decode and recover.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("persist-race", 1, 2);
  MPF_REQUIRE(set_id.valid());
  mpf_test::TempDirectory directory("persist-race");
  const std::string store = directory.path("store.bin");
  MPF_REQUIRE(fixture.engine().save_store(store).succeeded());

  constexpr int kSaves = 200;
  std::barrier gate(2);
  std::atomic<std::uint64_t> completed{0};
  std::atomic<std::uint64_t> failures{0};
  std::thread saver([&]() {
    gate.arrive_and_wait();
    for (int iteration = 0; iteration < kSaves; ++iteration) {
      const FabricOutcome outcome = fixture.engine().save_store(store);
      if (!outcome.succeeded()) {
        failures.fetch_add(1);
      }
      completed.fetch_add(1);
    }
  });
  gate.arrive_and_wait();
  for (int index = 0; index < 6; ++index) {
    const std::string path = "persist-race-" + std::to_string(index);
    MPF_REQUIRE(fixture.declare(path, 1).succeeded());
    const FabricOutcome outcome = fixture.add_member(set_id, path, 1);
    MPF_CHECK_MSG(outcome.succeeded(), outcome.render());
  }
  saver.join();
  MPF_CHECK_EQ(completed.load(), std::uint64_t{kSaves});
  MPF_CHECK_EQ(failures.load(), std::uint64_t{0});

  // Whatever generation the store holds, it must decode and recover.
  FabricEngine recovered;
  const FabricOutcome loaded = recovered.load_store(store);
  MPF_CHECK_MSG(loaded.succeeded(), loaded.render());
  MPF_CHECK(recovered.set_count() >= 1);
  const FabricIntegrityReport report = fixture.engine().check_integrity();
  MPF_CHECK_MSG(report.consistent, report.render());
}
