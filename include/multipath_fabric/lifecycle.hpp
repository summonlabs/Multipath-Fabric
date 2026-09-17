// Explicit lifecycle, currentness and readiness state models.
//
// Multipath Fabric refuses arbitrary state transitions. Every lifecycle change
// in the engine passes through the transition tables declared here, and those
// tables are exercised exhaustively by the test suite (every state/event pair).
//
// STATE MODEL
// -----------
// Set lifecycle (10 states):
//   DECLARED         created and durably recorded, membership may be assembled,
//                    not yet offered as an authoritative simultaneous-use set.
//   ACTIVE           published, usable members >= minimum requirement.
//   DEGRADED         published, at least one usable member, below the minimum.
//   EXHAUSTED        published, zero usable members.
//   ADMIN_DISABLED   administrative intent forbids use even though members may
//                    be individually authorized and current.
//   WITHDRAWING      withdrawal accepted, not yet complete.
//   WITHDRAWN        withdrawal complete; never authoritative again.
//   SUPERSEDED       replaced by a successor set; lineage preserved.
//   REVOKED          durably, generation-bound revoked with a reason code.
//   RETIRED          terminal; never reactivated by any late completion.
//
// Set currentness (2 values): CURRENT | REVALIDATION_REQUIRED. Currentness is a
// separate axis from lifecycle because the two facts are independent. A set can
// be ACTIVE with currentness REVALIDATION_REQUIRED (immediately after a
// coordinator restart, before revalidation completes) and it can be EXHAUSTED
// with currentness CURRENT. Collapsing the axes would destroy that distinction.
#ifndef MULTIPATH_FABRIC_LIFECYCLE_HPP
#define MULTIPATH_FABRIC_LIFECYCLE_HPP

#include <cstdint>
#include <optional>
#include <string_view>

namespace multipath_fabric {

enum class SetLifecycle : std::uint8_t {
  DECLARED = 1,
  ACTIVE = 2,
  DEGRADED = 3,
  EXHAUSTED = 4,
  ADMIN_DISABLED = 5,
  WITHDRAWING = 6,
  WITHDRAWN = 7,
  SUPERSEDED = 8,
  REVOKED = 9,
  RETIRED = 10,
};

inline constexpr std::uint8_t kSetLifecycleMin = 1;
inline constexpr std::uint8_t kSetLifecycleMax = 10;

// Events that can be applied to a set. The engine applies exactly these and
// rejects anything else at the DECODE stage.
enum class SetEvent : std::uint8_t {
  DECLARE = 1,
  PUBLISH = 2,
  MEMBER_ADDED = 3,
  MEMBER_REMOVED = 4,
  MEMBER_REPLACED = 5,
  // Membership inputs changed; the published lifecycle is recomputed.
  MEMBERSHIP_RECHECK = 6,
  MINIMUM_CHANGED = 7,
  POLICY_CHANGED = 8,
  ADMIN_DISABLED = 9,
  ADMIN_ENABLED = 10,
  REVALIDATE_SET = 11,
  // The governing coordinator epoch advanced; live currentness is lost.
  EPOCH_ADVANCE = 12,
  BEGIN_WITHDRAW = 13,
  COMPLETE_WITHDRAW = 14,
  SUPERSEDE = 15,
  REVOKE = 16,
  RETIRE = 17,
  // A member's Path Authority inputs were invalidated.
  DEPENDENCY_INVALIDATED = 18,
};

inline constexpr std::uint8_t kSetEventMin = 1;
inline constexpr std::uint8_t kSetEventMax = 18;

// What the transition table says should happen.
//   REJECT              the state/event pair is not legal for this state model
//   STAY                legal, lifecycle unchanged
//   RECOMPUTE           legal, lifecycle re-derived from membership/policy
//   BECOME_PUBLISHED    legal, lifecycle derived as a published set
//   BECOME_*            legal, lifecycle becomes that concrete state
enum class SetTransitionAction : std::uint8_t {
  REJECT = 0,
  STAY = 1,
  RECOMPUTE = 2,
  BECOME_PUBLISHED = 3,
  BECOME_ADMIN_DISABLED = 4,
  BECOME_WITHDRAWING = 5,
  BECOME_WITHDRAWN = 6,
  BECOME_SUPERSEDED = 7,
  BECOME_REVOKED = 8,
  BECOME_RETIRED = 9,
};

[[nodiscard]] SetTransitionAction set_transition(SetLifecycle state, SetEvent event) noexcept;

// Derives the lifecycle of a published set from its usable member count, its
// minimum requirement and its administrative enablement. Exhaustive semantics:
//   !admin_enabled               -> ADMIN_DISABLED
//   usable >= minimum            -> ACTIVE
//   usable >= 1 and < minimum    -> DEGRADED
//   usable == 0 and minimum >= 1 -> EXHAUSTED
// A minimum of zero means "no minimum requirement", so such a set is ACTIVE as
// soon as it is published, even with zero usable members.
[[nodiscard]] SetLifecycle derive_published_lifecycle(std::uint64_t usable_members,
                                                      std::uint64_t minimum_usable,
                                                      bool admin_enabled) noexcept;

// ---------------------------------------------------------------------------
// Set currentness
// ---------------------------------------------------------------------------

enum class SetCurrentness : std::uint8_t {
  CURRENT = 1,
  REVALIDATION_REQUIRED = 2,
};

inline constexpr std::uint8_t kSetCurrentnessMin = 1;
inline constexpr std::uint8_t kSetCurrentnessMax = 2;

// ---------------------------------------------------------------------------
// Member lifecycle
// ---------------------------------------------------------------------------

enum class MemberLifecycle : std::uint8_t {
  PENDING = 1,
  CURRENT = 2,
  REVALIDATION_REQUIRED = 3,
  UNUSABLE = 4,
  WITHDRAWN = 5,
  SUPERSEDED = 6,
  RETIRED = 7,
};

inline constexpr std::uint8_t kMemberLifecycleMin = 1;
inline constexpr std::uint8_t kMemberLifecycleMax = 7;

enum class MemberEvent : std::uint8_t {
  ADMITTED = 1,
  INPUTS_USABLE = 2,
  INPUTS_STALE_AUTHORITY = 3,
  INPUTS_NOT_USABLE = 4,
  REVALIDATED_OK = 5,
  REVALIDATED_STALE = 6,
  WITHDRAW = 7,
  SUPERSEDE = 8,
  RETIRE = 9,
};

inline constexpr std::uint8_t kMemberEventMin = 1;
inline constexpr std::uint8_t kMemberEventMax = 9;

// Returns the resulting lifecycle, or nullopt when the state/event pair is not
// legal. The test suite asserts every one of the 7 x 9 pairs.
[[nodiscard]] std::optional<MemberLifecycle> member_transition(MemberLifecycle state,
                                                               MemberEvent event) noexcept;

// ---------------------------------------------------------------------------
// Member currentness
// ---------------------------------------------------------------------------

// Why a member's inputs are, or are not, currently usable. The cause is
// preserved exactly rather than collapsed into one "not usable" flag. In
// particular a stale Path Authority generation is distinguishable from an
// ordinary rejection, from revocation, from retirement and from withdrawal.
enum class MemberCurrentness : std::uint8_t {
  CURRENT = 1,
  STALE_PATH_AUTHORITY = 2,
  PATH_CONDITIONALLY_NOT_PERMITTED = 3,
  PATH_REVALIDATION_REQUIRED = 4,
  PATH_REJECTED = 5,
  PATH_REVOKED = 6,
  PATH_STALE = 7,
  PATH_RETIRED = 8,
  PATH_AUTHORITY_UNKNOWN = 9,
  ADMIN_DISABLED = 10,
  SET_NOT_USABLE = 11,
  EPOCH_STALE = 12,
  AUTHORITY_FENCED = 13,
  PENDING_EVALUATION = 14,
};

inline constexpr std::uint8_t kMemberCurrentnessMin = 1;
inline constexpr std::uint8_t kMemberCurrentnessMax = 14;

// A member counts toward the set's usable-member threshold only when both its
// lifecycle and its currentness are CURRENT.
[[nodiscard]] constexpr bool member_is_usable(MemberLifecycle lifecycle,
                                              MemberCurrentness currentness) noexcept {
  return lifecycle == MemberLifecycle::CURRENT && currentness == MemberCurrentness::CURRENT;
}

// ---------------------------------------------------------------------------
// Route-consumption readiness
// ---------------------------------------------------------------------------

// Route Fabric consumes this value instead of inferring readiness from a pile
// of low-level fields. "Ready" means only: these exact paths are currently
// governed members eligible for simultaneous use. It says nothing about
// distribution, weighting, hashing, diversity, congestion or reservation.
enum class RouteReadiness : std::uint8_t {
  READY = 1,
  DEGRADED_BUT_READY = 2,
  INSUFFICIENT_MEMBERS = 3,
  REVALIDATION_REQUIRED = 4,
  NOT_PUBLISHED = 5,
  ADMIN_DISABLED = 6,
  WITHDRAWN = 7,
  SUPERSEDED = 8,
  REVOKED = 9,
  RETIRED = 10,
};

inline constexpr std::uint8_t kRouteReadinessMin = 1;
inline constexpr std::uint8_t kRouteReadinessMax = 10;

[[nodiscard]] RouteReadiness route_readiness(SetLifecycle lifecycle,
                                             SetCurrentness currentness) noexcept;

// ---------------------------------------------------------------------------
// Rendering, parsing and numeric domain validation
// ---------------------------------------------------------------------------

[[nodiscard]] std::string_view to_string(SetLifecycle value) noexcept;
[[nodiscard]] std::string_view to_string(SetEvent value) noexcept;
[[nodiscard]] std::string_view to_string(SetTransitionAction value) noexcept;
[[nodiscard]] std::string_view to_string(SetCurrentness value) noexcept;
[[nodiscard]] std::string_view to_string(MemberLifecycle value) noexcept;
[[nodiscard]] std::string_view to_string(MemberEvent value) noexcept;
[[nodiscard]] std::string_view to_string(MemberCurrentness value) noexcept;
[[nodiscard]] std::string_view to_string(RouteReadiness value) noexcept;

[[nodiscard]] std::optional<SetLifecycle> parse_set_lifecycle(std::string_view text) noexcept;
[[nodiscard]] std::optional<SetEvent> parse_set_event(std::string_view text) noexcept;
[[nodiscard]] std::optional<MemberLifecycle> parse_member_lifecycle(
    std::string_view text) noexcept;
[[nodiscard]] std::optional<MemberCurrentness> parse_member_currentness(
    std::string_view text) noexcept;
[[nodiscard]] std::optional<SetCurrentness> parse_set_currentness(std::string_view text) noexcept;
[[nodiscard]] std::optional<RouteReadiness> parse_route_readiness(std::string_view text) noexcept;

// Numeric domain validation used by persistence and the wire codec so that a
// malformed enumerator is rejected rather than reinterpreted.
[[nodiscard]] bool valid_set_lifecycle(std::uint8_t raw) noexcept;
[[nodiscard]] bool valid_set_event(std::uint8_t raw) noexcept;
[[nodiscard]] bool valid_set_currentness(std::uint8_t raw) noexcept;
[[nodiscard]] bool valid_member_lifecycle(std::uint8_t raw) noexcept;
[[nodiscard]] bool valid_member_currentness(std::uint8_t raw) noexcept;
[[nodiscard]] bool valid_route_readiness(std::uint8_t raw) noexcept;

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_LIFECYCLE_HPP
