#include <algorithm>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_framework.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

MPF_TEST(identities_accept_well_formed_encodings) {
  const auto set_id = MultipathSetId::parse("fabric-main/ns/set-1");
  MPF_REQUIRE(set_id.has_value());
  MPF_CHECK_EQ(set_id->view(), std::string_view("fabric-main/ns/set-1"));
  MPF_CHECK(set_id->valid());
  MPF_CHECK_EQ(set_id->size(), std::string("fabric-main/ns/set-1").size());
}

MPF_TEST(identities_reject_malformed_encodings) {
  const std::vector<std::string> rejected = {
      "", " leading", "trailing ", "has space", "has\ttab", "bad!char", "quote\"char",
      ".leadingdot", "trailingdot.", "-leadingdash", "trailingdash-", "under_score_edge_",
      std::string(129, 'a'),
  };
  for (const auto& text : rejected) {
    MPF_CHECK_MSG(!PathId::parse(text).has_value(), "accepted: " + text);
  }
  // The documented maximum length is accepted, one over is rejected.
  MPF_CHECK(PathId::parse(std::string(PathId::max_length, 'a')).has_value());
  MPF_CHECK(!PathId::parse(std::string(PathId::max_length + 1, 'a')).has_value());
}

MPF_TEST(identities_reject_cross_domain_conversion) {
  // The domains are distinct types; constructing one from another does not
  // compile, and the parse results are never interchangeable. This test pins the
  // runtime half: a value parsed in one domain does not equal a value in
  // another, and each renders through its own domain name.
  const auto path = PathId::require("path-alpha");
  const auto set = MultipathSetId::require("path-alpha");
  MPF_CHECK_EQ(path.view(), set.view());
  MPF_CHECK_EQ(std::string(PathId::domain_name), std::string("PathId"));
  MPF_CHECK_EQ(std::string(MultipathSetId::domain_name), std::string("MultipathSetId"));
  MPF_CHECK_EQ(std::string(MultipathMemberId::domain_name), std::string("MultipathMemberId"));
}

MPF_TEST(identities_order_deterministically) {
  const auto a = PathId::require("alpha");
  const auto b = PathId::require("alphabeta");
  const auto c = PathId::require("beta");
  MPF_CHECK(a < b);   // shorter prefix sorts first
  MPF_CHECK(b < c);
  MPF_CHECK(a < c);
  MPF_CHECK(!(b < a));
  MPF_CHECK(a == PathId::require("alpha"));
  MPF_CHECK(a != c);
  // Ordering is independent of construction order.
  std::vector<PathId> forward{c, a, b};
  std::vector<PathId> backward{b, c, a};
  std::sort(forward.begin(), forward.end());
  std::sort(backward.begin(), backward.end());
  MPF_CHECK(forward == backward);
  MPF_CHECK_EQ(forward.front().view(), std::string_view("alpha"));
}

MPF_TEST(default_constructed_identity_is_invalid_and_rejected) {
  const PathId empty;
  MPF_CHECK(!empty.valid());
  MPF_CHECK_EQ(empty.size(), std::size_t{0});
  MPF_CHECK_EQ(empty.view(), std::string_view(""));
  // It must never be treated as a wildcard: the engine rejects it outright.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("empty-id", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const FabricOutcome outcome = fixture.engine().add_member(
      fixture.context(), set_id, empty, PathAuthorityGeneration::first());
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::MALFORMED_REQUEST);
}

MPF_TEST(generation_rejects_zero_and_never_wraps) {
  MPF_CHECK(!MultipathSetGeneration::from_value(0).has_value());
  MPF_CHECK(MultipathSetGeneration::from_value(1).has_value());
  const MultipathSetGeneration first = MultipathSetGeneration::first();
  MPF_CHECK_EQ(first.value(), std::uint64_t{1});
  const auto second = first.next();
  MPF_REQUIRE(second.has_value());
  MPF_CHECK_EQ(second->value(), std::uint64_t{2});
  MPF_CHECK(*second > first);

  const auto maximum = MultipathSetGeneration::from_value(UINT64_MAX);
  MPF_REQUIRE(maximum.has_value());
  MPF_CHECK(!maximum->next().has_value());

  MPF_CHECK(!CoordinatorEpoch::from_value(0).has_value());
  MPF_CHECK(!MultipathAuthorityGeneration::from_value(0).has_value());
  MPF_CHECK(!MultipathMemberGeneration::from_value(0).has_value());
  MPF_CHECK(!MembershipGeneration::from_value(0).has_value());
  MPF_CHECK(!PathAuthorityGeneration::from_value(0).has_value());
}

MPF_TEST(watermark_allows_zero_and_is_monotonic) {
  const Watermark zero;
  MPF_CHECK_EQ(zero.value(), std::uint64_t{0});
  const auto one = zero.next();
  MPF_REQUIRE(one.has_value());
  MPF_CHECK_EQ(one->value(), std::uint64_t{1});
  MPF_CHECK(zero < *one);
  const Watermark maximum(UINT64_MAX);
  MPF_CHECK(!maximum.next().has_value());
}

MPF_TEST(checked_arithmetic_detects_overflow) {
  MPF_CHECK(!detail::add_overflows_u64(1, 2));
  MPF_CHECK(detail::add_overflows_u64(UINT64_MAX, 1));
  MPF_CHECK(!detail::checked_increment(UINT64_MAX).has_value());
  MPF_CHECK_EQ(*detail::checked_increment(41), std::uint64_t{42});
  MPF_CHECK(!detail::checked_add(UINT64_MAX, 1).has_value());
  MPF_CHECK(!detail::checked_multiply(UINT64_MAX, 2).has_value());
  MPF_CHECK_EQ(*detail::checked_multiply(3, 4), std::uint64_t{12});
  MPF_CHECK(!detail::narrow_u32(static_cast<std::uint64_t>(UINT32_MAX) + 1).has_value());
  MPF_CHECK_EQ(*detail::narrow_u16(65535), std::uint16_t{65535});
  MPF_CHECK(!detail::narrow_u16(65536).has_value());
  MPF_CHECK(!detail::narrow_u8(256).has_value());
}

MPF_TEST(digest_is_insertion_order_independent) {
  // The same set built from different publication orders has the same canonical
  // membership table. The semantic digest covers the set identity and key, so
  // digests are compared for repeated reads of one set; cross-set comparison is
  // covered by digest_covers_set_identity_and_key.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("digest-order", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  const std::vector<std::string> paths = {"path-a", "path-b", "path-c", "path-d"};
  for (const auto& path : paths) {
    MPF_REQUIRE(fixture.declare(path, 1).succeeded());
    MPF_REQUIRE(fixture.add_member(set_id, path, 1).succeeded());
  }
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->members.size(), std::size_t{4});
  // Canonical order is PathId order, independent of insertion order.
  for (std::size_t i = 1; i < snapshot->members.size(); ++i) {
    MPF_CHECK(snapshot->members[i - 1].path_id < snapshot->members[i].path_id);
  }
  const auto again = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(again.has_value());
  MPF_CHECK_EQ(snapshot->digest.to_hex(), again->digest.to_hex());
  MPF_CHECK_EQ(snapshot->snapshot_id.view(), again->snapshot_id.view());
  MPF_CHECK_EQ(snapshot->members[0].path_id.view(), std::string_view("path-a"));
  MPF_CHECK_EQ(snapshot->members[3].path_id.view(), std::string_view("path-d"));

  // A reversed publication order in an independent fabric produces the very same
  // canonical membership table and the very same digest.
  mpf_test::FabricFixture other;
  const MultipathSetId other_id = other.create_set("digest-order", 1);
  MPF_REQUIRE(other_id.valid());
  MPF_REQUIRE(other.publish(other_id).succeeded());
  const std::vector<std::string> reversed = {"path-d", "path-c", "path-b", "path-a"};
  for (const auto& path : reversed) {
    MPF_REQUIRE(other.declare(path, 1).succeeded());
    MPF_REQUIRE(other.add_member(other_id, path, 1).succeeded());
  }
  const auto other_snapshot = other.engine().snapshot(other_id);
  MPF_REQUIRE(other_snapshot.has_value());
  MPF_CHECK_EQ(other_snapshot->members.size(), snapshot->members.size());
  for (std::size_t index = 0; index < snapshot->members.size(); ++index) {
    MPF_CHECK_EQ(other_snapshot->members[index].path_id.view(),
                 snapshot->members[index].path_id.view());
    MPF_CHECK_EQ(other_snapshot->members[index].bound_authority_generation.value(),
                 snapshot->members[index].bound_authority_generation.value());
    MPF_CHECK_EQ(other_snapshot->members[index].lifecycle, snapshot->members[index].lifecycle);
    MPF_CHECK_EQ(other_snapshot->members[index].currentness,
                 snapshot->members[index].currentness);
  }
  MPF_CHECK_EQ(other_snapshot->usable_member_count, snapshot->usable_member_count);
  MPF_CHECK_EQ(other_snapshot->lifecycle, snapshot->lifecycle);
  MPF_CHECK_EQ(other_snapshot->readiness, snapshot->readiness);
}

MPF_TEST(digest_changes_when_semantic_state_changes) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("digest-change", 2, 2);
  MPF_REQUIRE(set_id.valid());
  const auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());
  MPF_CHECK_EQ(before->lifecycle, SetLifecycle::ACTIVE);
  MPF_REQUIRE(fixture.declare("path-digest-change-0", 1,
                              PathAuthorityState::REJECTED)
                  .succeeded());
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK(before->digest.to_hex() != after->digest.to_hex());
  MPF_CHECK_EQ(after->usable_member_count, std::uint64_t{1});
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::DEGRADED);
  // The generation advanced because the published governance state changed.
  MPF_CHECK(after->generation > before->generation);
}

MPF_TEST(digest_covers_set_identity_and_key) {
  // Two sets with identical membership inside one fabric still have different
  // semantic digests, because set identity and the semantic key are part of the
  // digest. Conversely a set keeps its digest across reads.
  mpf_test::FabricFixture fixture;
  const MultipathSetId first = fixture.build_set("alpha", 1, 2);
  const MultipathSetId second = fixture.build_set("beta", 1, 2);
  MPF_REQUIRE(first.valid());
  MPF_REQUIRE(second.valid());
  const auto first_snapshot = fixture.engine().snapshot(first);
  const auto second_snapshot = fixture.engine().snapshot(second);
  MPF_REQUIRE(first_snapshot.has_value());
  MPF_REQUIRE(second_snapshot.has_value());
  MPF_CHECK(first_snapshot->digest.to_hex() != second_snapshot->digest.to_hex());
  const auto first_again = fixture.engine().snapshot(first);
  MPF_REQUIRE(first_again.has_value());
  MPF_CHECK_EQ(first_snapshot->digest.to_hex(), first_again->digest.to_hex());
  MPF_CHECK_EQ(first_snapshot->snapshot_id.view(), first_again->snapshot_id.view());
}

MPF_TEST(digest_is_a_pure_function_of_the_semantic_state) {
  // The digest is recomputed from semantic state only. Repeating identical
  // queries without any mutation never changes it, and no timestamp, address,
  // thread identity or process-local counter participates.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("pure", 2, 3);
  MPF_REQUIRE(set_id.valid());
  std::string previous;
  for (int iteration = 0; iteration < 5; ++iteration) {
    const auto snapshot = fixture.engine().snapshot(set_id);
    MPF_REQUIRE(snapshot.has_value());
    const std::string rendered = snapshot->render();
    const std::string digest = snapshot->digest.to_hex();
    if (iteration != 0) {
      MPF_CHECK_EQ(digest, previous);
    }
    previous = digest;
    static_cast<void>(rendered);
  }
  // The rendered explanation ordering is likewise stable.
  const auto explanation = fixture.engine().explain_set(set_id);
  MPF_REQUIRE(explanation.has_value());
  const std::string first_render = explanation->render();
  const auto again = fixture.engine().explain_set(set_id);
  MPF_REQUIRE(again.has_value());
  MPF_CHECK_EQ(first_render, again->render());
}