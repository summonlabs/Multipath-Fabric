// Structured, deterministic explanations.
//
// Operators must be able to ask why a set is in its current state, why a member
// does not count, why a mutation was rejected, which publisher owns mutation
// authority and which epoch governs a set. Every answer is a structured value
// with a deterministic human rendering; nothing is recomputed at render time.
#ifndef MULTIPATH_FABRIC_EXPLANATION_HPP
#define MULTIPATH_FABRIC_EXPLANATION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"
#include "multipath_fabric/outcome.hpp"
#include "multipath_fabric/path_authority.hpp"
#include "multipath_fabric/snapshot.hpp"

namespace multipath_fabric {

enum class ExplanationReason : std::uint8_t {
  SET_PUBLISHED_AND_THRESHOLD_MET = 1,
  SET_BELOW_MINIMUM = 2,
  SET_ZERO_USABLE_MEMBERS = 3,
  SET_ADMIN_DISABLED = 4,
  SET_CURRENTNESS_NOT_ESTABLISHED = 5,
  SET_NOT_PUBLISHED = 6,
  SET_WITHDRAWN = 7,
  SET_SUPERSEDED = 8,
  SET_REVOKED = 9,
  SET_RETIRED = 10,
  MEMBER_USABLE = 11,
  MEMBER_PATH_AUTHORITY_GENERATION_STALE = 12,
  MEMBER_PATH_STATE_NOT_USABLE = 13,
  MEMBER_PATH_CONDITIONALLY_NOT_PERMITTED = 14,
  MEMBER_PATH_AUTHORITY_UNKNOWN = 15,
  MEMBER_ADMIN_DISABLED = 16,
  MEMBER_LIFECYCLE_NOT_CURRENT = 17,
  MEMBER_SET_NOT_USABLE = 18,
  MEMBER_EPOCH_STALE = 19,
  MEMBER_AUTHORITY_FENCED = 20,
  MEMBER_PENDING_EVALUATION = 21,
  MEMBER_PENDING_REVALIDATION = 22,
  MINIMUM_MEMBERSHIP_UNSATISFIED = 23,
  EXPLANATION_TRUNCATED = 24,
};

[[nodiscard]] std::string_view to_string(ExplanationReason reason) noexcept;
[[nodiscard]] bool valid_explanation_reason(std::uint8_t raw) noexcept;

struct MemberExplanation {
  MultipathMemberId id;
  PathId path_id;
  MemberLifecycle lifecycle = MemberLifecycle::PENDING;
  MemberCurrentness currentness = MemberCurrentness::PENDING_EVALUATION;
  bool admin_enabled = true;
  bool usable = false;
  PathAuthorityGeneration bound_authority_generation;
  // What Path Authority currently reports for the exact path, when a source is
  // bound. These are observations, never authority.
  std::optional<PathAuthorityGeneration> observed_authority_generation;
  std::optional<PathAuthorityState> observed_authority_state;
  std::uint32_t pending_revalidations = 0;
  ExplanationReason reason = ExplanationReason::MEMBER_USABLE;

  [[nodiscard]] std::string render() const;
};

struct SetExplanation {
  MultipathSetId set_id;
  SetKey key;
  SetLifecycle lifecycle = SetLifecycle::DECLARED;
  SetCurrentness currentness = SetCurrentness::CURRENT;
  RouteReadiness readiness = RouteReadiness::NOT_PUBLISHED;
  std::uint64_t member_count = 0;
  std::uint64_t usable_member_count = 0;
  std::uint64_t minimum_usable_members = 0;
  bool minimum_satisfied = false;
  bool admin_enabled = true;
  bool conditional_authority_permitted = false;
  CoordinatorEpoch governing_epoch;
  MultipathAuthorityGeneration authority_generation;
  std::optional<PublisherId> last_mutating_publisher;
  MembershipCause last_cause = MembershipCause::DECLARED;
  std::vector<ExplanationReason> reasons;
  std::vector<MemberExplanation> members;
  bool truncated = false;

  [[nodiscard]] std::string render() const;
};

struct RejectionExplanation {
  OutcomeCode code = OutcomeCode::OK;
  RejectionStage stage = RejectionStage::NONE;
  // 1-based position of the stage in the fixed rejection precedence.
  std::uint8_t precedence = 0;
  std::string detail;
  std::string guidance;

  [[nodiscard]] std::string render() const;
};

// Derives the structured rejection explanation for a failed outcome.
[[nodiscard]] RejectionExplanation explain_rejection(const FabricOutcome& outcome);

// Every stage of the fixed rejection precedence, in order, for documentation
// and for the CLI.
[[nodiscard]] std::vector<RejectionStage> rejection_precedence();

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_EXPLANATION_HPP
