#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

constexpr std::string_view kPaths[] = {"prop-a", "prop-b", "prop-c", "prop-d", "prop-e"};
constexpr std::uint64_t kPathCount = 5;

struct Schedule {
  std::vector<std::string> sets;
  std::vector<std::string> members;
};

// Validates every structural property of one set and returns a description of
// the first violation, or an empty string when the state is consistent.
[[nodiscard]] std::string check_invariants(const FabricEngine& engine,
                                           const MultipathSetId& set_id) {
  const auto snapshot = engine.snapshot(set_id);
  if (!snapshot.has_value()) {
    return "snapshot missing";
  }
  // No duplicate current path membership.
  std::set<std::string> paths;
  std::set<std::string> member_ids;
  std::uint64_t usable = 0;
  for (const auto& member : snapshot->members) {
    if (!paths.insert(member.path_id.str()).second) {
      return "duplicate path in membership table";
    }
    if (!member_ids.insert(member.id.str()).second) {
      return "duplicate member identity";
    }
    if (member.usable) {
      ++usable;
      if (member.lifecycle != MemberLifecycle::CURRENT ||
          member.currentness != MemberCurrentness::CURRENT) {
        return "member reported usable without both axes current";
      }
    }
  }
  if (usable != snapshot->usable_member_count) {
    return "usable_member_count does not equal the number of usable members";
  }
  if (snapshot->usable_member_count > snapshot->member_count) {
    return "usable count exceeds member count";
  }
  if (snapshot->member_count != snapshot->members.size()) {
    return "member_count does not match the member table";
  }
  // Canonical ordering: strictly increasing PathId order.
  for (std::size_t index = 1; index < snapshot->members.size(); ++index) {
    if (!(snapshot->members[index - 1].path_id < snapshot->members[index].path_id)) {
      return "members are not in canonical PathId order";
    }
  }
  // Threshold invariant while currentness holds.
  if (snapshot->currentness == SetCurrentness::CURRENT) {
    if (snapshot->lifecycle == SetLifecycle::ACTIVE &&
        snapshot->usable_member_count < snapshot->minimum_usable_members) {
      return "ACTIVE below the minimum usable-member requirement";
    }
    if (snapshot->lifecycle == SetLifecycle::DEGRADED &&
        (snapshot->usable_member_count == 0 ||
         snapshot->usable_member_count >= snapshot->minimum_usable_members)) {
      return "DEGRADED with an impossible usable count";
    }
    if (snapshot->lifecycle == SetLifecycle::EXHAUSTED &&
        snapshot->usable_member_count != 0) {
      return "EXHAUSTED with usable members";
    }
  }
  // Stale Path Authority never counts as usable.
  for (const auto& member : snapshot->members) {
    if (member.currentness == MemberCurrentness::STALE_PATH_AUTHORITY && member.usable) {
      return "stale Path Authority generation counted as usable";
    }
  }
  // Terminal sets are never authoritative.
  if (snapshot->lifecycle == SetLifecycle::RETIRED ||
      snapshot->lifecycle == SetLifecycle::REVOKED ||
      snapshot->lifecycle == SetLifecycle::SUPERSEDED ||
      snapshot->lifecycle == SetLifecycle::WITHDRAWN) {
    const RouteReadiness readiness = snapshot->readiness;
    if (readiness == RouteReadiness::READY || readiness == RouteReadiness::DEGRADED_BUT_READY) {
      return "terminal set reported as ready for consumption";
    }
    if (snapshot->currentness == SetCurrentness::CURRENT &&
        snapshot->lifecycle != SetLifecycle::WITHDRAWN) {
      return "terminal set reported live currentness";
    }
  }
  if (snapshot->digest.to_hex() != snapshot->snapshot_id.str().substr(5)) {
    return "snapshot identity is not the semantic digest";
  }
  return std::string();
}

}  // namespace

namespace {
void run_one_schedule(std::uint64_t seed);
}  // namespace

MPF_TEST(property_randomised_schedule_preserves_every_invariant) {
  const std::vector<std::uint64_t> seeds = {1, 7, 42, 1337, 987654321, 20260101};
  for (const std::uint64_t seed : seeds) {
    // One schedule per scope keeps the frame small; the schedule itself is long
    // lived enough that the analyzer can see the whole body.
    run_one_schedule(seed);
  }
}

namespace {

void run_one_schedule(std::uint64_t seed) {
  {
    mpf_test::Random random(seed);
    mpf_test::FabricFixture fixture(seed);
    const MultipathSetId set_id = fixture.create_set("property", 2);
    MPF_REQUIRE(set_id.valid());
    MPF_REQUIRE(fixture.publish(set_id).succeeded());
    const auto initial = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(initial.has_value());
    MultipathSetGeneration previous_generation = initial->generation;

    for (int step = 0; step < 200; ++step) {
      const std::uint64_t choice = random.below(10);
      const std::string path(kPaths[random.below(kPathCount)]);
      if (choice < 3) {
        // Declare a Path Authority view, sometimes at a new generation.
        const std::uint64_t generation = 1 + random.below(3);
        const auto state = static_cast<PathAuthorityState>(1 + random.below(7));
        const FabricOutcome outcome = fixture.declare(path, generation, state);
        MPF_CHECK_MSG(outcome.succeeded(), "declare failed seed=" + std::to_string(seed) +
                                               " step=" + std::to_string(step));
      } else if (choice < 5) {
        const FabricOutcome outcome = fixture.add_member(set_id, path, 1);
        if (!outcome.succeeded()) {
          // Only structured rejections are allowed.
          MPF_CHECK_MSG(outcome.code == OutcomeCode::DUPLICATE_MEMBER ||
                            outcome.code == OutcomeCode::PATH_AUTHORITY_UNKNOWN ||
                            outcome.code == OutcomeCode::PATH_NOT_USABLE ||
                            outcome.code == OutcomeCode::STALE_PATH_AUTHORITY,
                        "unexpected add rejection " + std::string(to_string(outcome.code)) +
                            " seed=" + std::to_string(seed));
        }
      } else if (choice < 7) {
        const auto snapshot = fixture.engine().snapshot(set_id);
        MPF_REQUIRE(snapshot.has_value());
        std::vector<MultipathMemberId> live;
        for (const auto& member : snapshot->members) {
          if (member.lifecycle != MemberLifecycle::WITHDRAWN &&
              member.lifecycle != MemberLifecycle::SUPERSEDED &&
              member.lifecycle != MemberLifecycle::RETIRED) {
            live.push_back(member.id);
          }
        }
        if (!live.empty()) {
          const MultipathMemberId member = live[random.below(live.size())];
          const FabricOutcome outcome =
              fixture.engine().withdraw_member(fixture.context(), set_id, member, "schedule");
          MPF_CHECK_MSG(outcome.succeeded(),
                        "withdraw failed " + std::string(to_string(outcome.code)) +
                            " seed=" + std::to_string(seed));
        }
      } else if (choice < 8) {
        const FabricOutcome outcome = fixture.revalidate(set_id);
        MPF_CHECK_MSG(outcome.succeeded(), "revalidate failed " +
                                               std::string(to_string(outcome.code)) +
                                               " seed=" + std::to_string(seed));
      } else if (choice < 9) {
        const auto snapshot = fixture.engine().snapshot(set_id);
        MPF_REQUIRE(snapshot.has_value());
        // Only live membership relations can be revalidated; a withdrawn or
        // superseded relation is frozen and is refused by design.
        std::vector<MultipathMemberId> live;
        for (const auto& member : snapshot->members) {
          if (member.lifecycle != MemberLifecycle::WITHDRAWN &&
              member.lifecycle != MemberLifecycle::SUPERSEDED &&
              member.lifecycle != MemberLifecycle::RETIRED) {
            live.push_back(member.id);
          }
        }
        if (!live.empty()) {
          const MultipathMemberId member = live[random.below(live.size())];
          const FabricOutcome outcome =
              fixture.engine().revalidate_member(fixture.context(), set_id, member);
          MPF_CHECK_MSG(outcome.succeeded(),
                        "member revalidate failed " + std::string(to_string(outcome.code)) +
                            " seed=" + std::to_string(seed));
        }
      } else {
        const FabricOutcome outcome = fixture.engine().set_minimum_usable_members(
            fixture.context(), set_id, random.below(5));
        MPF_CHECK_MSG(outcome.succeeded(), "minimum change failed " +
                                               std::string(to_string(outcome.code)));
      }

      const std::string problem = check_invariants(fixture.engine(), set_id);
      MPF_CHECK_MSG(problem.empty(), problem + " seed=" + std::to_string(seed) +
                                         " step=" + std::to_string(step));
      const FabricIntegrityReport report = fixture.engine().check_integrity();
      MPF_CHECK_MSG(report.consistent,
                    "index integrity: " + report.render() + " seed=" + std::to_string(seed) +
                        " step=" + std::to_string(step));

      const auto snapshot = fixture.engine().snapshot(set_id);
      MPF_REQUIRE(snapshot.has_value());
      // Set generation never decreases.
      MPF_CHECK_MSG(!(snapshot->generation < previous_generation),
                    "set generation decreased seed=" + std::to_string(seed));
      previous_generation = snapshot->generation;
      // Digest determinism across repeated reads.
      const auto again = fixture.engine().snapshot(set_id);
      MPF_REQUIRE(again.has_value());
      MPF_CHECK_EQ(again->digest.to_hex(), snapshot->digest.to_hex());
    }

    // Persistence round-trip at the end of every schedule.
    mpf_test::TempDirectory directory("property");
    const std::string store = directory.path("store.bin");
    MPF_CHECK(fixture.engine().save_store(store).succeeded());
    FabricEngine recovered;
    const FabricOutcome loaded = recovered.load_store(store);
    MPF_CHECK(loaded.succeeded());
    const auto original = fixture.engine().snapshot(set_id);
    const auto restored = recovered.snapshot(set_id);
    MPF_REQUIRE(original.has_value());
    MPF_REQUIRE(restored.has_value());
    MPF_CHECK_EQ(restored->member_count, original->member_count);
    MPF_CHECK_EQ(restored->generation.value(), original->generation.value());
    MPF_CHECK_EQ(restored->render().find("currentness=REVALIDATION_REQUIRED") !=
                     std::string::npos,
                 true);
  }
}

}  // namespace

MPF_TEST(property_stale_authority_never_mutates) {
  mpf_test::Random random(2024);
  for (int iteration = 0; iteration < 50; ++iteration) {
    mpf_test::FabricFixture fixture(static_cast<std::uint64_t>(iteration) + 1);
    const MultipathSetId set_id = fixture.build_set("stale-worker", 1, 2);
    MPF_REQUIRE(set_id.valid());
    const auto before = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(before.has_value());

    const std::uint64_t mode = random.below(3);
    MutationContext context = fixture.context();
    if (mode == 0) {
      context.epoch = CoordinatorEpoch::require(fixture.engine().epoch().value() +
                                                random.below(5) + 1);
    } else if (mode == 1) {
      context.worker_boot = WorkerBootId::require("never-registered-boot");
    } else {
      context.publisher = PublisherId::require("never-registered-publisher");
    }
    MPF_REQUIRE(fixture.declare("path-stale-worker-new", 1).succeeded());
    const FabricOutcome outcome =
        fixture.engine().add_member(context, set_id, PathId::require("path-stale-worker-new"),
                                    PathAuthorityGeneration::require(1));
    MPF_CHECK(!outcome.succeeded());
    const auto after = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(after.has_value());
    // A rejected authority check changes nothing at all.
    MPF_CHECK_EQ(after->digest.to_hex(), before->digest.to_hex());
    MPF_CHECK_EQ(after->generation.value(), before->generation.value());
  }
}

MPF_TEST(property_retired_sets_never_become_current) {
  mpf_test::Random random(777);
  for (int iteration = 0; iteration < 50; ++iteration) {
    mpf_test::FabricFixture fixture(static_cast<std::uint64_t>(iteration) + 100);
    const MultipathSetId set_id = fixture.build_set("terminal", 1, 3);
    MPF_REQUIRE(set_id.valid());
    const std::uint64_t mode = random.below(4);
    switch (mode) {
      case 0:
        MPF_REQUIRE(fixture.engine().retire_set(fixture.context(), set_id, "done").succeeded());
        break;
      case 1:
        MPF_REQUIRE(fixture.engine()
                        .revoke_set(fixture.context(), set_id, RevocationReason::SECURITY, "x")
                        .succeeded());
        break;
      case 2:
        MPF_REQUIRE(fixture.engine().withdraw_set(fixture.context(), set_id, "drain").succeeded());
        MPF_REQUIRE(fixture.engine().complete_withdrawal(fixture.context(), set_id).succeeded());
        break;
      default: {
        const MultipathSetId successor = fixture.build_set("terminal-successor", 1, 1);
        MPF_REQUIRE(successor.valid());
        MPF_REQUIRE(fixture.engine().supersede_set(fixture.context(), set_id, successor).succeeded());
        break;
      }
    }
    // Every route that could reactivate the set is refused.
    MPF_REQUIRE(fixture.declare("terminal-late-path", 1).succeeded());
    const std::vector<FabricOutcome> attempts = {
        fixture.add_member(set_id, "terminal-late-path", 1),
        fixture.publish(set_id),
        fixture.revalidate(set_id),
        fixture.engine().set_admin_enabled(fixture.context(), set_id, true),
        fixture.engine().set_minimum_usable_members(fixture.context(), set_id, 1),
    };
    for (const auto& outcome : attempts) {
      MPF_CHECK(!outcome.succeeded());
    }
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    MPF_CHECK(snapshot->readiness != RouteReadiness::READY);
    MPF_CHECK(snapshot->readiness != RouteReadiness::DEGRADED_BUT_READY);
    MPF_CHECK_MSG(check_invariants(fixture.engine(), set_id).empty(),
                  check_invariants(fixture.engine(), set_id));
  }
}

MPF_TEST(property_replay_and_generations_are_stable) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("replay", 1, 2);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.declare("replay-extra", 1).succeeded());
  MutationContext context = fixture.context();
  const FabricOutcome created =
      fixture.engine().add_member(context, set_id, PathId::require("replay-extra"),
                                  PathAuthorityGeneration::require(1));
  MPF_REQUIRE(created.succeeded());
  const auto baseline = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(baseline.has_value());
  for (int replay = 0; replay < 5; ++replay) {
    const FabricOutcome outcome =
        fixture.engine().add_member(context, set_id, PathId::require("replay-extra"),
                                    PathAuthorityGeneration::require(1));
    MPF_CHECK_EQ(outcome.code, OutcomeCode::IDEMPOTENT);
  }
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->generation.value(), baseline->generation.value());
  MPF_CHECK_EQ(after->membership_generation.value(), baseline->membership_generation.value());
  MPF_CHECK_EQ(after->digest.to_hex(), baseline->digest.to_hex());
}
