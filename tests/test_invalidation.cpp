#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

MPF_TEST(invalidation_touches_only_dependent_sets) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId alpha = fixture.build_set("inv-alpha", 2, 3);
  const MultipathSetId beta = fixture.build_set("inv-beta", 2, 3);
  MPF_REQUIRE(alpha.valid());
  MPF_REQUIRE(beta.valid());

  const auto alpha_before = fixture.engine().snapshot(alpha);
  const auto beta_before = fixture.engine().snapshot(beta);
  MPF_REQUIRE(alpha_before.has_value());
  MPF_REQUIRE(beta_before.has_value());

  // The reverse index reports exactly the dependent sets of one exact path.
  const std::vector<MultipathSetId> dependents =
      fixture.engine().sets_for_path(PathId::require("path-inv-alpha-0"));
  MPF_CHECK_EQ(dependents.size(), std::size_t{1});
  if (!dependents.empty()) {
    MPF_CHECK_EQ(dependents.front().view(), alpha.view());
  }
  MPF_CHECK_EQ(fixture.engine().sets_for_path(PathId::require("no-such-path")).size(),
               std::size_t{0});

  const FabricOutcome invalidated =
      fixture.declare("path-inv-alpha-0", 1, PathAuthorityState::REJECTED);
  MPF_CHECK(invalidated.succeeded());
  MPF_CHECK_EQ(invalidated.code, OutcomeCode::PATH_INVALIDATED);

  const auto alpha_after = fixture.engine().snapshot(alpha);
  const auto beta_after = fixture.engine().snapshot(beta);
  MPF_REQUIRE(alpha_after.has_value());
  MPF_REQUIRE(beta_after.has_value());
  MPF_CHECK_EQ(alpha_after->usable_member_count, std::uint64_t{2});
  MPF_CHECK_EQ(alpha_after->lifecycle, SetLifecycle::ACTIVE);
  // The unrelated set is byte-for-byte unchanged.
  MPF_CHECK_EQ(beta_after->digest.to_hex(), beta_before->digest.to_hex());
  MPF_CHECK_EQ(beta_after->generation.value(), beta_before->generation.value());

  // Invalidating a path that no set uses changes nothing at all.
  MPF_REQUIRE(fixture.declare("orphan-path", 1, PathAuthorityState::REJECTED).succeeded());
  const auto alpha_final = fixture.engine().snapshot(alpha);
  MPF_REQUIRE(alpha_final.has_value());
  MPF_CHECK_EQ(alpha_final->digest.to_hex(), alpha_after->digest.to_hex());
}

MPF_TEST(stale_path_authority_generation_never_counts_as_usable) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("stale-generation", 1, 2);
  MPF_REQUIRE(set_id.valid());
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});

  // Path Authority advances the generation and still reports AUTHORIZED. The
  // member is bound to the previous generation and must not count.
  MPF_REQUIRE(fixture.declare("path-stale-generation-0", 2,
                              PathAuthorityState::AUTHORIZED)
                  .succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});
  const MemberSnapshot* member = snapshot->find_member(PathId::require("path-stale-generation-0"));
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::STALE_PATH_AUTHORITY);
  MPF_CHECK_EQ(member->lifecycle, MemberLifecycle::REVALIDATION_REQUIRED);
  MPF_CHECK(!member->usable);
  MPF_CHECK_EQ(member->bound_authority_generation.value(), std::uint64_t{1});

  // An explicit member revalidation rebinds the member to the current
  // generation and restores usability.
  const FabricOutcome revalidated =
      fixture.engine().revalidate_member(fixture.context(), set_id, member->id);
  MPF_CHECK(revalidated.succeeded());
  MPF_CHECK_EQ(revalidated.code, OutcomeCode::MEMBER_REVALIDATED);
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  member = snapshot->find_member(PathId::require("path-stale-generation-0"));
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK_EQ(member->bound_authority_generation.value(), std::uint64_t{2});
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::CURRENT);
  MPF_CHECK(member->usable);
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{2});
}

MPF_TEST(member_revalidation_reports_a_negative_result_without_rejecting) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("negative", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;
  MPF_REQUIRE(fixture.declare("path-negative-0", 1, PathAuthorityState::REJECTED).succeeded());

  const FabricOutcome outcome =
      fixture.engine().revalidate_member(fixture.context(), set_id, member_id);
  // The evaluation completed, so this is not a rejection; the member simply is
  // not usable and the cause is preserved.
  MPF_CHECK(outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::MEMBER_REVALIDATION_NEGATIVE);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  const MemberSnapshot* member = after->find_member(member_id);
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::PATH_REJECTED);
  MPF_CHECK_EQ(member->lifecycle, MemberLifecycle::UNUSABLE);
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::EXHAUSTED);

  // Revocation and retirement of a path are preserved as distinct causes.
  MPF_REQUIRE(fixture.declare("path-negative-0", 1, PathAuthorityState::REVOKED).succeeded());
  const auto revoked = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(revoked.has_value());
  MPF_CHECK_EQ(revoked->find_member(member_id)->currentness, MemberCurrentness::PATH_REVOKED);
  MPF_REQUIRE(fixture.declare("path-negative-0", 1, PathAuthorityState::RETIRED).succeeded());
  const auto retired = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(retired.has_value());
  MPF_CHECK_EQ(retired->find_member(member_id)->currentness, MemberCurrentness::PATH_RETIRED);
  MPF_REQUIRE(fixture.declare("path-negative-0", 1, PathAuthorityState::STALE).succeeded());
  const auto stale = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(stale.has_value());
  MPF_CHECK_EQ(stale->find_member(member_id)->currentness, MemberCurrentness::PATH_STALE);
  MPF_REQUIRE(fixture.declare("path-negative-0", 1,
                              PathAuthorityState::REVALIDATION_REQUIRED)
                  .succeeded());
  const auto needs = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(needs.has_value());
  MPF_CHECK_EQ(needs->find_member(member_id)->currentness,
               MemberCurrentness::PATH_REVALIDATION_REQUIRED);
}

MPF_TEST(conditional_authorization_requires_explicit_policy) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId strict = fixture.create_set("conditional-strict", 1, true, false);
  MPF_REQUIRE(strict.valid());
  MPF_REQUIRE(fixture.publish(strict).succeeded());
  MPF_REQUIRE(fixture.declare("conditional-path", 1,
                              PathAuthorityState::CONDITIONALLY_AUTHORIZED)
                  .succeeded());
  const FabricOutcome refused = fixture.add_member(strict, "conditional-path", 1);
  MPF_CHECK(!refused.succeeded());
  MPF_CHECK_EQ(refused.code, OutcomeCode::PATH_NOT_USABLE);
  MPF_CHECK_EQ(refused.stage, RejectionStage::PATH_AUTHORITY);

  const MultipathSetId permissive = fixture.create_set("conditional-permissive", 1, true, true);
  MPF_REQUIRE(permissive.valid());
  MPF_REQUIRE(fixture.publish(permissive).succeeded());
  const FabricOutcome accepted = fixture.add_member(permissive, "conditional-path", 1);
  MPF_CHECK(accepted.succeeded());
  const auto snapshot = fixture.engine().snapshot(permissive);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});
  MPF_CHECK_EQ(snapshot->find_member(PathId::require("conditional-path"))->currentness,
               MemberCurrentness::CURRENT);

  // Withdrawing the policy demotes the member with a distinct cause.
  const FabricOutcome changed = fixture.engine().set_conditional_authority_policy(
      fixture.context(), permissive, false);
  MPF_CHECK(changed.succeeded());
  const auto after = fixture.engine().snapshot(permissive);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->find_member(PathId::require("conditional-path"))->currentness,
               MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED);
  MPF_CHECK_EQ(after->usable_member_count, std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// Invalidation watermark: the mandatory stale-completion race
// ---------------------------------------------------------------------------

MPF_TEST(stale_revalidation_completion_cannot_restore_current_state) {
  // 1. Member P is bound to Path Authority generation 8 and is usable.
  // 2. A two-phase revalidation begins and captures the member watermark.
  // 3. Path Authority advances P to generation 9, invalidating generation 8.
  // 4. The stale completion arrives.
  // 5. It must be refused and must not restore generation 8 as current.
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("watermark", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  const PathId path = PathId::require("watermark-path");
  MPF_REQUIRE(fixture.declare("watermark-path", 8).succeeded());
  MPF_REQUIRE(fixture.add_member(set_id, "watermark-path", 8).succeeded());

  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});
  const MultipathMemberId member_id = snapshot->members.front().id;

  const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member_id, RevalidationAttemptId::require("reval-attempt-1"));
  MPF_REQUIRE(begun.outcome.succeeded());
  MPF_REQUIRE(begun.ticket.has_value());
  const RevalidationTicket ticket = *begun.ticket;
  MPF_CHECK_EQ(ticket.bound_authority_generation.value(), std::uint64_t{8});

  // Path Authority advances to generation 9 and invalidates generation 8.
  MPF_REQUIRE(fixture.declare("watermark-path", 9,
                              PathAuthorityState::AUTHORIZED)
                  .succeeded());
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{0});
  MPF_CHECK_EQ(snapshot->find_member(member_id)->currentness,
               MemberCurrentness::STALE_PATH_AUTHORITY);

  // The stale completion carries the generation 8 view it observed at begin.
  PathAuthorityView stale_view;
  stale_view.path = path;
  stale_view.generation = PathAuthorityGeneration::require(8);
  stale_view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome completion = fixture.engine().complete_member_revalidation(
      fixture.context(), ticket, stale_view);
  MPF_CHECK(!completion.succeeded());
  MPF_CHECK_EQ(completion.code, OutcomeCode::STALE_REVALIDATION);
  MPF_CHECK_EQ(completion.stage, RejectionStage::PATH_AUTHORITY);

  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MemberSnapshot* member = snapshot->find_member(member_id);
  MPF_REQUIRE(member != nullptr);
  MPF_CHECK(!member->usable);
  MPF_CHECK_EQ(member->bound_authority_generation.value(), std::uint64_t{8});
  MPF_CHECK_EQ(member->currentness, MemberCurrentness::STALE_PATH_AUTHORITY);
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{0});
  MPF_CHECK_EQ(member->pending_revalidations, std::uint32_t{0});

  // A fresh two-phase revalidation against the current view succeeds.
  const RevalidationBegin fresh = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member_id, RevalidationAttemptId::require("reval-attempt-2"));
  MPF_REQUIRE(fresh.outcome.succeeded());
  MPF_REQUIRE(fresh.ticket.has_value());
  PathAuthorityView current_view;
  current_view.path = path;
  current_view.generation = PathAuthorityGeneration::require(9);
  current_view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome accepted =
      fixture.engine().complete_member_revalidation(fixture.context(), *fresh.ticket, current_view);
  MPF_CHECK(accepted.succeeded());
  MPF_CHECK_EQ(accepted.code, OutcomeCode::MEMBER_REVALIDATED);
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->find_member(member_id)->bound_authority_generation.value(),
               std::uint64_t{9});
  MPF_CHECK_EQ(snapshot->usable_member_count, std::uint64_t{1});
}

MPF_TEST(revalidation_ticket_is_invalidated_by_withdrawal_and_retirement) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("ticket-set", 1, 2);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId first = snapshot->members[0].id;
  const MultipathMemberId second = snapshot->members[1].id;

  const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, first, RevalidationAttemptId::require("ticket-a"));
  MPF_REQUIRE(begun.outcome.succeeded());
  MPF_REQUIRE(begun.ticket.has_value());

  // Withdrawing the very member under revalidation invalidates the outstanding
  // ticket: the member's own inputs changed while the revalidation was in
  // flight. (Withdrawing a different member leaves this member's inputs alone
  // and is deliberately not treated as an invalidation.)
  static_cast<void>(second);
  MPF_REQUIRE(fixture.engine()
                  .withdraw_member(fixture.context(), set_id, first, "drained")
                  .succeeded());
  PathAuthorityView view;
  view.path = snapshot->members[0].path_id;
  view.generation = PathAuthorityGeneration::require(1);
  view.state = PathAuthorityState::AUTHORIZED;
  const FabricOutcome stale =
      fixture.engine().complete_member_revalidation(fixture.context(), *begun.ticket, view);
  MPF_CHECK(!stale.succeeded());
  MPF_CHECK_EQ(stale.code, OutcomeCode::STALE_REVALIDATION);

  // Retiring the set invalidates any outstanding ticket as well.
  const RevalidationBegin second_begin = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, second, RevalidationAttemptId::require("ticket-b"));
  MPF_REQUIRE(second_begin.outcome.succeeded());
  MPF_REQUIRE(second_begin.ticket.has_value());
  MPF_REQUIRE(fixture.engine().retire_set(fixture.context(), set_id, "end of life").succeeded());
  const FabricOutcome retired =
      fixture.engine().complete_member_revalidation(fixture.context(), *second_begin.ticket, view);
  MPF_CHECK(!retired.succeeded());
  MPF_CHECK(retired.code == OutcomeCode::STALE_REVALIDATION ||
            retired.code == OutcomeCode::RETIRED);
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::RETIRED);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::RETIRED);
}

MPF_TEST(abandoned_revalidation_releases_the_pending_counter) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("abandon", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;

  const RevalidationBegin begun = fixture.engine().begin_member_revalidation(
      fixture.context(), set_id, member_id, RevalidationAttemptId::require("abandon-a"));
  MPF_REQUIRE(begun.outcome.succeeded());
  auto pending = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(pending.has_value());
  MPF_CHECK_EQ(pending->find_member(member_id)->pending_revalidations, std::uint32_t{1});

  MPF_REQUIRE(fixture.engine().abandon_member_revalidation(*begun.ticket).succeeded());
  pending = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(pending.has_value());
  MPF_CHECK_EQ(pending->find_member(member_id)->pending_revalidations, std::uint32_t{0});

  // Abandoning twice is refused rather than underflowing the counter.
  const FabricOutcome twice = fixture.engine().abandon_member_revalidation(*begun.ticket);
  MPF_CHECK(!twice.succeeded());
  MPF_CHECK_EQ(twice.code, OutcomeCode::MALFORMED_REQUEST);
}

MPF_TEST(retirement_prevents_late_reactivation) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("retire", 1, 2);
  MPF_REQUIRE(set_id.valid());
  const auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());

  MPF_REQUIRE(fixture.engine().retire_set(fixture.context(), set_id, "decommissioned").succeeded());
  const auto retired = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(retired.has_value());
  MPF_CHECK_EQ(retired->lifecycle, SetLifecycle::RETIRED);
  for (const auto& member : retired->members) {
    MPF_CHECK_EQ(member.lifecycle, MemberLifecycle::RETIRED);
    MPF_CHECK(!member.usable);
  }

  // Every late completion is refused and the set never becomes authoritative.
  MPF_REQUIRE(fixture.declare("retire-new-path", 1).succeeded());
  MPF_CHECK_EQ(fixture.add_member(set_id, "retire-new-path", 1).code, OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.publish(set_id).code, OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.engine().set_admin_enabled(fixture.context(), set_id, true).code,
               OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.engine().set_minimum_usable_members(fixture.context(), set_id, 1).code,
               OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.engine().set_conditional_authority_policy(fixture.context(), set_id, true).code,
               OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.engine()
                   .remove_member(fixture.context(), set_id, before->members.front().id, "late")
                   .code,
               OutcomeCode::RETIRED);
  MPF_CHECK_EQ(fixture.engine()
                   .revalidate_member(fixture.context(), set_id, before->members.front().id)
                   .code,
               OutcomeCode::RETIRED);
  // A late dependency invalidation changes nothing at all.
  const FabricOutcome invalidated =
      fixture.declare("path-retire-0", 1, PathAuthorityState::REJECTED);
  MPF_CHECK(invalidated.succeeded());
  const auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::RETIRED);
  MPF_CHECK_EQ(after->digest.to_hex(), retired->digest.to_hex());
}

MPF_TEST(revocation_is_distinct_and_idempotent) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("revoke", 1, 2);
  MPF_REQUIRE(set_id.valid());
  const auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());

  const FabricOutcome revoked = fixture.engine().revoke_set(
      fixture.context(), set_id, RevocationReason::SECURITY, "credential withdrawn");
  MPF_CHECK(revoked.succeeded());
  MPF_CHECK_EQ(revoked.code, OutcomeCode::SET_REVOKED);
  auto after = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->lifecycle, SetLifecycle::REVOKED);
  MPF_REQUIRE(after->revocation.has_value());
  MPF_CHECK_EQ(after->revocation->reason, RevocationReason::SECURITY);
  MPF_CHECK_EQ(after->revocation->detail, std::string("credential withdrawn"));
  MPF_CHECK_EQ(after->revocation->generation.value(), after->generation.value());
  MPF_CHECK_EQ(after->readiness, RouteReadiness::REVOKED);
  // Revocation is not member withdrawal and not set retirement: member records
  // keep their own lifecycle while recording that the owning set is unusable.
  for (const auto& member : after->members) {
    MPF_CHECK_EQ(member.currentness, MemberCurrentness::SET_NOT_USABLE);
    MPF_CHECK(member.lifecycle != MemberLifecycle::RETIRED);
    MPF_CHECK(member.lifecycle != MemberLifecycle::WITHDRAWN);
  }

  // Idempotent with the same reason code and detail.
  const FabricOutcome again = fixture.engine().revoke_set(
      fixture.context(), set_id, RevocationReason::SECURITY, "credential withdrawn");
  MPF_CHECK(again.succeeded());
  MPF_CHECK_EQ(again.code, OutcomeCode::IDEMPOTENT);
  const auto unchanged = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(unchanged.has_value());
  MPF_CHECK_EQ(unchanged->generation.value(), after->generation.value());
  MPF_CHECK_EQ(unchanged->digest.to_hex(), after->digest.to_hex());

  // A different reason code is refused rather than silently overwriting.
  const FabricOutcome different = fixture.engine().revoke_set(
      fixture.context(), set_id, RevocationReason::ADMINISTRATIVE, "other");
  MPF_CHECK(!different.succeeded());
  MPF_CHECK_EQ(different.code, OutcomeCode::REVOKED);

  // Revoked sets reject every mutation.
  MPF_CHECK_EQ(fixture.publish(set_id).code, OutcomeCode::REVOKED);
  MPF_CHECK_EQ(fixture.revalidate(set_id).code, OutcomeCode::REVOKED);
  const FabricOutcome retired = fixture.engine().retire_set(fixture.context(), set_id, "later");
  MPF_CHECK(retired.succeeded());
  MPF_CHECK_EQ(retired.code, OutcomeCode::SET_RETIRED);
  const auto final_state = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(final_state.has_value());
  MPF_CHECK_EQ(final_state->lifecycle, SetLifecycle::RETIRED);
  // The durable revocation record survives retirement.
  MPF_REQUIRE(final_state->revocation.has_value());
  MPF_CHECK_EQ(final_state->revocation->reason, RevocationReason::SECURITY);
}

MPF_TEST(supersession_leaves_no_simultaneous_authority) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId old_set = fixture.build_set("supersede-old", 1, 2);
  const MultipathSetId new_set = fixture.build_set("supersede-new", 1, 2);
  MPF_REQUIRE(old_set.valid());
  MPF_REQUIRE(new_set.valid());
  MPF_CHECK_EQ(fixture.engine().readiness(old_set).value(), RouteReadiness::READY);
  MPF_CHECK_EQ(fixture.engine().readiness(new_set).value(), RouteReadiness::READY);

  const FabricOutcome superseded =
      fixture.engine().supersede_set(fixture.context(), old_set, new_set);
  MPF_CHECK(superseded.succeeded());
  MPF_CHECK_EQ(superseded.code, OutcomeCode::SET_SUPERSEDED);

  const auto old_snapshot = fixture.engine().snapshot(old_set);
  const auto new_snapshot = fixture.engine().snapshot(new_set);
  MPF_REQUIRE(old_snapshot.has_value());
  MPF_REQUIRE(new_snapshot.has_value());
  MPF_CHECK_EQ(old_snapshot->lifecycle, SetLifecycle::SUPERSEDED);
  MPF_CHECK_EQ(old_snapshot->readiness, RouteReadiness::SUPERSEDED);
  MPF_REQUIRE(old_snapshot->superseded_by.has_value());
  MPF_CHECK_EQ(old_snapshot->superseded_by->view(), new_set.view());
  MPF_REQUIRE(new_snapshot->supersedes.has_value());
  MPF_CHECK_EQ(new_snapshot->supersedes->view(), old_set.view());
  // Exactly one of the two remains authoritative.
  const bool old_ready = old_snapshot->readiness == RouteReadiness::READY ||
                         old_snapshot->readiness == RouteReadiness::DEGRADED_BUT_READY;
  const bool new_ready = new_snapshot->readiness == RouteReadiness::READY ||
                         new_snapshot->readiness == RouteReadiness::DEGRADED_BUT_READY;
  MPF_CHECK(!old_ready);
  MPF_CHECK(new_ready);

  // Supersession is idempotent for the same successor and refused for a
  // different one.
  const FabricOutcome again = fixture.engine().supersede_set(fixture.context(), old_set, new_set);
  MPF_CHECK(again.succeeded());
  MPF_CHECK_EQ(again.code, OutcomeCode::IDEMPOTENT);
  const MultipathSetId third = fixture.build_set("supersede-third", 1, 1);
  MPF_REQUIRE(third.valid());
  MPF_CHECK_EQ(fixture.engine().supersede_set(fixture.context(), old_set, third).code,
               OutcomeCode::SUPERSEDED);
}

MPF_TEST(withdrawal_is_two_phase_and_distinct_from_retirement) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("withdraw-set", 1, 2);
  MPF_REQUIRE(set_id.valid());

  const FabricOutcome withdrawing =
      fixture.engine().withdraw_set(fixture.context(), set_id, "drain for maintenance");
  MPF_CHECK(withdrawing.succeeded());
  MPF_CHECK_EQ(withdrawing.code, OutcomeCode::SET_WITHDRAWING);
  auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::WITHDRAWING);
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::WITHDRAWN);
  MPF_CHECK_EQ(snapshot->withdrawal_reason, std::string("drain for maintenance"));
  for (const auto& member : snapshot->members) {
    MPF_CHECK_EQ(member.lifecycle, MemberLifecycle::WITHDRAWN);
  }
  // A withdrawal in progress accepts no membership growth.
  MPF_REQUIRE(fixture.declare("path-withdraw-set-late", 1).succeeded());
  MPF_CHECK_EQ(fixture.add_member(set_id, "path-withdraw-set-late", 1).code,
               OutcomeCode::WITHDRAWN);

  const FabricOutcome completed = fixture.engine().complete_withdrawal(fixture.context(), set_id);
  MPF_CHECK(completed.succeeded());
  MPF_CHECK_EQ(completed.code, OutcomeCode::SET_WITHDRAWN);
  snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_CHECK_EQ(snapshot->lifecycle, SetLifecycle::WITHDRAWN);
  MPF_CHECK_EQ(snapshot->currentness, SetCurrentness::REVALIDATION_REQUIRED);
  // Withdrawn is not retired and not revoked.
  MPF_CHECK(!snapshot->revocation.has_value());
  MPF_CHECK_EQ(snapshot->readiness, RouteReadiness::WITHDRAWN);
  const FabricOutcome retired = fixture.engine().retire_set(fixture.context(), set_id, "final");
  MPF_CHECK(retired.succeeded());
  MPF_CHECK_EQ(retired.code, OutcomeCode::SET_RETIRED);
}

MPF_TEST(unknown_path_rejects_member_admission) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.create_set("unknown-path", 1);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.publish(set_id).succeeded());
  const FabricOutcome outcome = fixture.add_member(set_id, "path-never-declared", 1);
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::PATH_AUTHORITY_UNKNOWN);
  MPF_CHECK_EQ(outcome.stage, RejectionStage::PATH_AUTHORITY);
}
