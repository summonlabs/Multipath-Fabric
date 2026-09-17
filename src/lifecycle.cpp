#include "multipath_fabric/lifecycle.hpp"

#include <array>

namespace multipath_fabric {
namespace {

constexpr std::size_t kStateCount = 10;
constexpr std::size_t kEventCount = 18;

using Row = std::array<SetTransitionAction, kEventCount>;
using Table = std::array<Row, kStateCount>;

constexpr std::size_t si(SetLifecycle state) noexcept {
  return static_cast<std::size_t>(state) - 1;
}
constexpr std::size_t ei(SetEvent event) noexcept {
  return static_cast<std::size_t>(event) - 1;
}

constexpr SetTransitionAction R = SetTransitionAction::REJECT;
constexpr SetTransitionAction S = SetTransitionAction::STAY;
constexpr SetTransitionAction C = SetTransitionAction::RECOMPUTE;
constexpr SetTransitionAction P = SetTransitionAction::BECOME_PUBLISHED;
constexpr SetTransitionAction W = SetTransitionAction::BECOME_WITHDRAWING;
constexpr SetTransitionAction D = SetTransitionAction::BECOME_WITHDRAWN;
constexpr SetTransitionAction U = SetTransitionAction::BECOME_SUPERSEDED;
constexpr SetTransitionAction V = SetTransitionAction::BECOME_REVOKED;
constexpr SetTransitionAction T = SetTransitionAction::BECOME_RETIRED;
constexpr SetTransitionAction X = SetTransitionAction::BECOME_ADMIN_DISABLED;

// The complete set transition table. Columns follow SetEvent 1..18 exactly:
//   DECLARE PUBLISH MEMBER_ADDED MEMBER_REMOVED MEMBER_REPLACED
//   MEMBERSHIP_RECHECK MINIMUM_CHANGED POLICY_CHANGED ADMIN_DISABLED
//   ADMIN_ENABLED REVALIDATE_SET EPOCH_ADVANCE BEGIN_WITHDRAW
//   COMPLETE_WITHDRAW SUPERSEDE REVOKE RETIRE DEPENDENCY_INVALIDATED
constexpr Table kTable{{
    // DECLARED
    Row{R, P, S, S, S, S, S, S, S, S, S, S, C, R, U, V, T, S},
    // ACTIVE
    Row{R, R, C, C, C, C, C, C, X, C, C, S, W, R, U, V, T, C},
    // DEGRADED
    Row{R, R, C, C, C, C, C, C, X, C, C, S, W, R, U, V, T, C},
    // EXHAUSTED
    Row{R, R, C, C, C, C, C, C, X, C, C, S, W, R, U, V, T, C},
    // ADMIN_DISABLED
    Row{R, R, S, S, S, S, S, S, R, C, S, S, W, R, U, V, T, S},
    // WITHDRAWING
    Row{R, R, R, S, R, S, R, R, R, R, R, S, R, D, U, V, T, S},
    // WITHDRAWN
    Row{R, R, R, R, R, R, R, R, R, R, R, S, R, R, R, V, T, R},
    // SUPERSEDED
    Row{R, R, R, R, R, R, R, R, R, R, R, S, R, R, R, R, T, R},
    // REVOKED
    Row{R, R, R, R, R, R, R, R, R, R, R, S, R, R, R, R, T, R},
    // RETIRED
    Row{R, R, R, R, R, R, R, R, R, R, R, S, R, R, R, R, R, R},
}};

// Member transition table. Rows follow MemberLifecycle 1..7, columns follow
// MemberEvent 1..9: ADMITTED INPUTS_USABLE INPUTS_STALE_AUTHORITY
// INPUTS_NOT_USABLE REVALIDATED_OK REVALIDATED_STALE WITHDRAW SUPERSEDE RETIRE
using MRow = std::array<std::optional<MemberLifecycle>, 9>;
using MTable = std::array<MRow, 7>;

constexpr auto N = std::nullopt;
constexpr auto MP = MemberLifecycle::PENDING;
constexpr auto MC = MemberLifecycle::CURRENT;
constexpr auto MR = MemberLifecycle::REVALIDATION_REQUIRED;
constexpr auto MU = MemberLifecycle::UNUSABLE;
constexpr auto MW = MemberLifecycle::WITHDRAWN;
constexpr auto MS = MemberLifecycle::SUPERSEDED;
constexpr auto MT = MemberLifecycle::RETIRED;

constexpr MTable kMemberTable{{
    // PENDING
    MRow{MP, MC, MR, MU, MC, MR, MW, MS, MT},
    // CURRENT
    MRow{N, MC, MR, MU, MC, MR, MW, MS, MT},
    // REVALIDATION_REQUIRED
    MRow{N, N, MR, MU, MC, MR, MW, MS, MT},
    // UNUSABLE
    MRow{N, N, MR, MU, MC, MR, MW, MS, MT},
    // WITHDRAWN
    MRow{N, N, N, N, N, N, N, MS, MT},
    // SUPERSEDED
    MRow{N, N, N, N, N, N, N, N, MT},
    // RETIRED -- terminal
    MRow{N, N, N, N, N, N, N, N, N},
}};

}  // namespace

SetTransitionAction set_transition(SetLifecycle state, SetEvent event) noexcept {
  const auto state_raw = static_cast<std::uint8_t>(state);
  const auto event_raw = static_cast<std::uint8_t>(event);
  if (state_raw < kSetLifecycleMin || state_raw > kSetLifecycleMax ||
      event_raw < kSetEventMin || event_raw > kSetEventMax) {
    return SetTransitionAction::REJECT;
  }
  return kTable[si(state)][ei(event)];
}

SetLifecycle derive_published_lifecycle(std::uint64_t usable_members,
                                        std::uint64_t minimum_usable,
                                        bool admin_enabled) noexcept {
  if (!admin_enabled) {
    return SetLifecycle::ADMIN_DISABLED;
  }
  if (usable_members >= minimum_usable) {
    return SetLifecycle::ACTIVE;
  }
  if (usable_members >= 1) {
    return SetLifecycle::DEGRADED;
  }
  return SetLifecycle::EXHAUSTED;
}

std::optional<MemberLifecycle> member_transition(MemberLifecycle state,
                                                 MemberEvent event) noexcept {
  const auto state_raw = static_cast<std::uint8_t>(state);
  const auto event_raw = static_cast<std::uint8_t>(event);
  if (state_raw < kMemberLifecycleMin || state_raw > kMemberLifecycleMax ||
      event_raw < kMemberEventMin || event_raw > kMemberEventMax) {
    return std::nullopt;
  }
  return kMemberTable[static_cast<std::size_t>(state_raw) - 1]
                     [static_cast<std::size_t>(event_raw) - 1];
}

RouteReadiness route_readiness(SetLifecycle lifecycle, SetCurrentness currentness) noexcept {
  switch (lifecycle) {
    case SetLifecycle::RETIRED:
      return RouteReadiness::RETIRED;
    case SetLifecycle::REVOKED:
      return RouteReadiness::REVOKED;
    case SetLifecycle::SUPERSEDED:
      return RouteReadiness::SUPERSEDED;
    case SetLifecycle::WITHDRAWN:
    case SetLifecycle::WITHDRAWING:
      return RouteReadiness::WITHDRAWN;
    case SetLifecycle::DECLARED:
      return RouteReadiness::NOT_PUBLISHED;
    case SetLifecycle::ADMIN_DISABLED:
      return RouteReadiness::ADMIN_DISABLED;
    case SetLifecycle::EXHAUSTED:
      // A stale set that has zero usable members reports REVALIDATION_REQUIRED
      // because re-establishing currentness is the operation that can change
      // the answer; the membership deficit is reported alongside it.
      return currentness == SetCurrentness::CURRENT ? RouteReadiness::INSUFFICIENT_MEMBERS
                                                    : RouteReadiness::REVALIDATION_REQUIRED;
    case SetLifecycle::DEGRADED:
      return currentness == SetCurrentness::CURRENT ? RouteReadiness::DEGRADED_BUT_READY
                                                    : RouteReadiness::REVALIDATION_REQUIRED;
    case SetLifecycle::ACTIVE:
      return currentness == SetCurrentness::CURRENT ? RouteReadiness::READY
                                                    : RouteReadiness::REVALIDATION_REQUIRED;
  }
  return RouteReadiness::REVALIDATION_REQUIRED;
}

std::string_view to_string(SetLifecycle value) noexcept {
  switch (value) {
    case SetLifecycle::DECLARED: return "DECLARED";
    case SetLifecycle::ACTIVE: return "ACTIVE";
    case SetLifecycle::DEGRADED: return "DEGRADED";
    case SetLifecycle::EXHAUSTED: return "EXHAUSTED";
    case SetLifecycle::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case SetLifecycle::WITHDRAWING: return "WITHDRAWING";
    case SetLifecycle::WITHDRAWN: return "WITHDRAWN";
    case SetLifecycle::SUPERSEDED: return "SUPERSEDED";
    case SetLifecycle::REVOKED: return "REVOKED";
    case SetLifecycle::RETIRED: return "RETIRED";
  }
  return "<invalid-set-lifecycle>";
}

std::string_view to_string(SetEvent value) noexcept {
  switch (value) {
    case SetEvent::DECLARE: return "DECLARE";
    case SetEvent::PUBLISH: return "PUBLISH";
    case SetEvent::MEMBER_ADDED: return "MEMBER_ADDED";
    case SetEvent::MEMBER_REMOVED: return "MEMBER_REMOVED";
    case SetEvent::MEMBER_REPLACED: return "MEMBER_REPLACED";
    case SetEvent::MEMBERSHIP_RECHECK: return "MEMBERSHIP_RECHECK";
    case SetEvent::MINIMUM_CHANGED: return "MINIMUM_CHANGED";
    case SetEvent::POLICY_CHANGED: return "POLICY_CHANGED";
    case SetEvent::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case SetEvent::ADMIN_ENABLED: return "ADMIN_ENABLED";
    case SetEvent::REVALIDATE_SET: return "REVALIDATE_SET";
    case SetEvent::EPOCH_ADVANCE: return "EPOCH_ADVANCE";
    case SetEvent::BEGIN_WITHDRAW: return "BEGIN_WITHDRAW";
    case SetEvent::COMPLETE_WITHDRAW: return "COMPLETE_WITHDRAW";
    case SetEvent::SUPERSEDE: return "SUPERSEDE";
    case SetEvent::REVOKE: return "REVOKE";
    case SetEvent::RETIRE: return "RETIRE";
    case SetEvent::DEPENDENCY_INVALIDATED: return "DEPENDENCY_INVALIDATED";
  }
  return "<invalid-set-event>";
}

std::string_view to_string(SetTransitionAction value) noexcept {
  switch (value) {
    case SetTransitionAction::REJECT: return "REJECT";
    case SetTransitionAction::STAY: return "STAY";
    case SetTransitionAction::RECOMPUTE: return "RECOMPUTE";
    case SetTransitionAction::BECOME_PUBLISHED: return "BECOME_PUBLISHED";
    case SetTransitionAction::BECOME_ADMIN_DISABLED: return "BECOME_ADMIN_DISABLED";
    case SetTransitionAction::BECOME_WITHDRAWING: return "BECOME_WITHDRAWING";
    case SetTransitionAction::BECOME_WITHDRAWN: return "BECOME_WITHDRAWN";
    case SetTransitionAction::BECOME_SUPERSEDED: return "BECOME_SUPERSEDED";
    case SetTransitionAction::BECOME_REVOKED: return "BECOME_REVOKED";
    case SetTransitionAction::BECOME_RETIRED: return "BECOME_RETIRED";
  }
  return "<invalid-set-transition-action>";
}

std::string_view to_string(SetCurrentness value) noexcept {
  switch (value) {
    case SetCurrentness::CURRENT: return "CURRENT";
    case SetCurrentness::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
  }
  return "<invalid-set-currentness>";
}

std::string_view to_string(MemberLifecycle value) noexcept {
  switch (value) {
    case MemberLifecycle::PENDING: return "PENDING";
    case MemberLifecycle::CURRENT: return "CURRENT";
    case MemberLifecycle::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case MemberLifecycle::UNUSABLE: return "UNUSABLE";
    case MemberLifecycle::WITHDRAWN: return "WITHDRAWN";
    case MemberLifecycle::SUPERSEDED: return "SUPERSEDED";
    case MemberLifecycle::RETIRED: return "RETIRED";
  }
  return "<invalid-member-lifecycle>";
}

std::string_view to_string(MemberEvent value) noexcept {
  switch (value) {
    case MemberEvent::ADMITTED: return "ADMITTED";
    case MemberEvent::INPUTS_USABLE: return "INPUTS_USABLE";
    case MemberEvent::INPUTS_STALE_AUTHORITY: return "INPUTS_STALE_AUTHORITY";
    case MemberEvent::INPUTS_NOT_USABLE: return "INPUTS_NOT_USABLE";
    case MemberEvent::REVALIDATED_OK: return "REVALIDATED_OK";
    case MemberEvent::REVALIDATED_STALE: return "REVALIDATED_STALE";
    case MemberEvent::WITHDRAW: return "WITHDRAW";
    case MemberEvent::SUPERSEDE: return "SUPERSEDE";
    case MemberEvent::RETIRE: return "RETIRE";
  }
  return "<invalid-member-event>";
}

std::string_view to_string(MemberCurrentness value) noexcept {
  switch (value) {
    case MemberCurrentness::CURRENT: return "CURRENT";
    case MemberCurrentness::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED:
      return "PATH_CONDITIONALLY_NOT_PERMITTED";
    case MemberCurrentness::PATH_REVALIDATION_REQUIRED: return "PATH_REVALIDATION_REQUIRED";
    case MemberCurrentness::PATH_REJECTED: return "PATH_REJECTED";
    case MemberCurrentness::PATH_REVOKED: return "PATH_REVOKED";
    case MemberCurrentness::PATH_STALE: return "PATH_STALE";
    case MemberCurrentness::PATH_RETIRED: return "PATH_RETIRED";
    case MemberCurrentness::PATH_AUTHORITY_UNKNOWN: return "PATH_AUTHORITY_UNKNOWN";
    case MemberCurrentness::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case MemberCurrentness::SET_NOT_USABLE: return "SET_NOT_USABLE";
    case MemberCurrentness::EPOCH_STALE: return "EPOCH_STALE";
    case MemberCurrentness::AUTHORITY_FENCED: return "AUTHORITY_FENCED";
    case MemberCurrentness::PENDING_EVALUATION: return "PENDING_EVALUATION";
  }
  return "<invalid-member-currentness>";
}

std::string_view to_string(RouteReadiness value) noexcept {
  switch (value) {
    case RouteReadiness::READY: return "READY";
    case RouteReadiness::DEGRADED_BUT_READY: return "DEGRADED_BUT_READY";
    case RouteReadiness::INSUFFICIENT_MEMBERS: return "INSUFFICIENT_MEMBERS";
    case RouteReadiness::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case RouteReadiness::NOT_PUBLISHED: return "NOT_PUBLISHED";
    case RouteReadiness::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case RouteReadiness::WITHDRAWN: return "WITHDRAWN";
    case RouteReadiness::SUPERSEDED: return "SUPERSEDED";
    case RouteReadiness::REVOKED: return "REVOKED";
    case RouteReadiness::RETIRED: return "RETIRED";
  }
  return "<invalid-route-readiness>";
}

std::optional<SetLifecycle> parse_set_lifecycle(std::string_view text) noexcept {
  for (std::uint8_t raw = kSetLifecycleMin; raw <= kSetLifecycleMax; ++raw) {
    const auto candidate = static_cast<SetLifecycle>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<SetEvent> parse_set_event(std::string_view text) noexcept {
  for (std::uint8_t raw = kSetEventMin; raw <= kSetEventMax; ++raw) {
    const auto candidate = static_cast<SetEvent>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<MemberLifecycle> parse_member_lifecycle(std::string_view text) noexcept {
  for (std::uint8_t raw = kMemberLifecycleMin; raw <= kMemberLifecycleMax; ++raw) {
    const auto candidate = static_cast<MemberLifecycle>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<MemberCurrentness> parse_member_currentness(std::string_view text) noexcept {
  for (std::uint8_t raw = kMemberCurrentnessMin; raw <= kMemberCurrentnessMax; ++raw) {
    const auto candidate = static_cast<MemberCurrentness>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<SetCurrentness> parse_set_currentness(std::string_view text) noexcept {
  for (std::uint8_t raw = kSetCurrentnessMin; raw <= kSetCurrentnessMax; ++raw) {
    const auto candidate = static_cast<SetCurrentness>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<RouteReadiness> parse_route_readiness(std::string_view text) noexcept {
  for (std::uint8_t raw = kRouteReadinessMin; raw <= kRouteReadinessMax; ++raw) {
    const auto candidate = static_cast<RouteReadiness>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool valid_set_lifecycle(std::uint8_t raw) noexcept {
  return raw >= kSetLifecycleMin && raw <= kSetLifecycleMax;
}
bool valid_set_event(std::uint8_t raw) noexcept {
  return raw >= kSetEventMin && raw <= kSetEventMax;
}
bool valid_set_currentness(std::uint8_t raw) noexcept {
  return raw >= kSetCurrentnessMin && raw <= kSetCurrentnessMax;
}
bool valid_member_lifecycle(std::uint8_t raw) noexcept {
  return raw >= kMemberLifecycleMin && raw <= kMemberLifecycleMax;
}
bool valid_member_currentness(std::uint8_t raw) noexcept {
  return raw >= kMemberCurrentnessMin && raw <= kMemberCurrentnessMax;
}
bool valid_route_readiness(std::uint8_t raw) noexcept {
  return raw >= kRouteReadinessMin && raw <= kRouteReadinessMax;
}

}  // namespace multipath_fabric
