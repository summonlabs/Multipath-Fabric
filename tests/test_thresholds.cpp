#include <algorithm>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

[[nodiscard]] std::string label(std::uint64_t members, std::uint64_t minimum,
                                std::uint64_t unusable) {
  return "members=" + std::to_string(members) + " minimum=" + std::to_string(minimum) +
         " unusable=" + std::to_string(unusable);
}

[[nodiscard]] SetLifecycle expected_lifecycle(std::uint64_t usable, std::uint64_t minimum) {
  if (usable >= minimum) {
    return SetLifecycle::ACTIVE;
  }
  if (usable >= 1) {
    return SetLifecycle::DEGRADED;
  }
  return SetLifecycle::EXHAUSTED;
}

}  // namespace

MPF_TEST(minimum_member_matrix_is_exhaustive) {
  for (std::uint64_t members = 0; members <= 4; ++members) {
    for (std::uint64_t minimum = 0; minimum <= 4; ++minimum) {
      for (std::uint64_t unusable = 0; unusable <= members; ++unusable) {
        mpf_test::FabricFixture fixture;
        const std::string name = "matrix-" + std::to_string(members) + "-" +
                                 std::to_string(minimum) + "-" + std::to_string(unusable);
        const MultipathSetId set_id = fixture.create_set(name, minimum);
        MPF_REQUIRE(set_id.valid());
        MPF_REQUIRE(fixture.publish(set_id).succeeded());
        for (std::uint64_t index = 0; index < members; ++index) {
          const std::string path = "matrix-path-" + std::to_string(index);
          MPF_REQUIRE(fixture.declare(path, 1).succeeded());
          MPF_REQUIRE(fixture.add_member(set_id, path, 1).succeeded());
        }
        for (std::uint64_t index = 0; index < unusable; ++index) {
          const std::string path = "matrix-path-" + std::to_string(index);
          MPF_REQUIRE(fixture
                          .declare(path, 1, PathAuthorityState::REJECTED)
                          .succeeded());
        }
        const auto snapshot = fixture.engine().snapshot(set_id);
        MPF_REQUIRE(snapshot.has_value());
        const std::uint64_t usable = members - unusable;
        MPF_CHECK_MSG(snapshot->usable_member_count == usable,
                      label(members, minimum, unusable) + " usable count");
        MPF_CHECK_MSG(snapshot->member_count == members,
                      label(members, minimum, unusable) + " member count");
        MPF_CHECK_MSG(snapshot->minimum_usable_members == minimum,
                      label(members, minimum, unusable) + " minimum");
        MPF_CHECK_MSG(snapshot->lifecycle == expected_lifecycle(usable, minimum),
                      label(members, minimum, unusable) + " lifecycle expected " +
                          std::string(to_string(expected_lifecycle(usable, minimum))) + " got " +
                          std::string(to_string(snapshot->lifecycle)));
        // The core threshold invariant: while currentness holds, ACTIVE implies
        // the minimum requirement is satisfied.
        if (snapshot->lifecycle == SetLifecycle::ACTIVE &&
            snapshot->currentness == SetCurrentness::CURRENT) {
          MPF_CHECK_MSG(usable >= minimum, label(members, minimum, unusable) + " active below min");
        }
        MPF_CHECK(snapshot->usable_member_count <= snapshot->member_count);
        MPF_CHECK_EQ(snapshot->member_count, members);
      }
    }
  }
}

MPF_TEST(threshold_transitions_are_exact_at_every_boundary) {
  // Four members, minimum two: walk the usable count down and back up.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("walk", 2);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  const std::vector<std::string> paths = {"walk-0", "walk-1", "walk-2", "walk-3"};
  for (const auto& path : paths) {
    MPF_REQUIRE(fixture.declare(path, 1).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, path, 1).succeeded());
  }
  const auto lifecycle = [&]() {
    const auto snapshot = fixture.engine().snapshot(set_id);
    return snapshot.has_value() ? snapshot->lifecycle : SetLifecycle::RETIRED;
  };
  const auto usable = [&]() {
    const auto snapshot = fixture.engine().snapshot(set_id);
    return snapshot.has_value() ? snapshot->usable_member_count : std::uint64_t{999};
  };
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(usable(), std::uint64_t{4});

  // 4 -> 3 usable stays ACTIVE.
  MPF_REQUIRE(fixture.declare("walk-0", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{3});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::ACTIVE);

  // 3 -> 2 usable is exactly at the requirement: still ACTIVE.
  MPF_REQUIRE(fixture.declare("walk-1", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{2});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::ACTIVE);

  // 2 -> 1 usable is one below the requirement: DEGRADED.
  MPF_REQUIRE(fixture.declare("walk-2", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{1});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::DEGRADED);

  // 1 -> 0 usable: EXHAUSTED.
  MPF_REQUIRE(fixture.declare("walk-3", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{0});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::EXHAUSTED);

  // Reauthorizing at the SAME generation restores nothing until revalidation.
  MPF_REQUIRE(fixture.declare("walk-3", 1, PathAuthorityState::AUTHORIZED).succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{0});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::EXHAUSTED);

  // An explicit set revalidation re-evaluates every member against the current
  // Path Authority views and restores the count.
  const FabricOutcome revalidated = fixture.revalidate(set_id);
  MPF_CHECK(revalidated.succeeded());
  MPF_CHECK_EQ(usable(), std::uint64_t{1});
  MPF_CHECK_EQ(lifecycle(), SetLifecycle::DEGRADED);
  MPF_CHECK_EQ(revalidated.usable_members.has_value()
                   ? *revalidated.usable_members
                   : std::uint64_t{999},
               std::uint64_t{1});
}

MPF_TEST(zero_minimum_never_degrades) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("zero-minimum", 0);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{0});
  MPF_CHECK_EQ(snapshot->minimum_usable_members, std::uint64_t{0});
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::READY);
}

MPF_TEST(insufficient_members_rejection_is_reported_for_declared_sets) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("declared-empty", 2);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::DECLARED);
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::NOT_PUBLISHED);
}
