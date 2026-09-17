#include <array>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_framework.hpp"

using namespace multipath_fabric;

namespace {

// Expected set transition table, written independently of the implementation as
// one character per event. R=REJECT S=STAY C=RECOMPUTE P=BECOME_PUBLISHED
// X=BECOME_ADMIN_DISABLED W=BECOME_WITHDRAWING D=BECOME_WITHDRAWN
// U=BECOME_SUPERSEDED V=BECOME_REVOKED T=BECOME_RETIRED
const std::array<const char*, 10> kExpectedSetRows = {
    /* DECLARED       */ "RPSSSSSSSSSSCRUVTS",
    /* ACTIVE         */ "RRCCCCCCXCCSWRUVTC",
    /* DEGRADED       */ "RRCCCCCCXCCSWRUVTC",
    /* EXHAUSTED      */ "RRCCCCCCXCCSWRUVTC",
    /* ADMIN_DISABLED */ "RRSSSSSSRCSSWRUVTS",
    /* WITHDRAWING    */ "RRRSRSRRRRRSRDUVTS",
    /* WITHDRAWN      */ "RRRRRRRRRRRSRRRVTR",
    /* SUPERSEDED     */ "RRRRRRRRRRRSRRRRTR",
    /* REVOKED        */ "RRRRRRRRRRRSRRRRTR",
    /* RETIRED        */ "RRRRRRRRRRRSRRRRRR",
};

const std::array<const char*, 7> kExpectedMemberRows = {
    /* PENDING               */ "PCRUCRWST",
    /* CURRENT               */ "NCRUCRWST",
    /* REVALIDATION_REQUIRED */ "NNRUCRWST",
    /* UNUSABLE              */ "NNRUCRWST",
    /* WITHDRAWN             */ "NNNNNNNST",
    /* SUPERSEDED            */ "NNNNNNNNT",
    /* RETIRED               */ "NNNNNNNNN",
};

[[nodiscard]] char encode_set_action(SetTransitionAction action) {
  switch (action) {
    case SetTransitionAction::REJECT: return 'R';
    case SetTransitionAction::STAY: return 'S';
    case SetTransitionAction::RECOMPUTE: return 'C';
    case SetTransitionAction::BECOME_PUBLISHED: return 'P';
    case SetTransitionAction::BECOME_ADMIN_DISABLED: return 'X';
    case SetTransitionAction::BECOME_WITHDRAWING: return 'W';
    case SetTransitionAction::BECOME_WITHDRAWN: return 'D';
    case SetTransitionAction::BECOME_SUPERSEDED: return 'U';
    case SetTransitionAction::BECOME_REVOKED: return 'V';
    case SetTransitionAction::BECOME_RETIRED: return 'T';
  }
  return '?';
}

}  // namespace

MPF_TEST(set_transition_table_is_exhaustively_correct) {
  for (std::uint8_t state_raw = kSetLifecycleMin; state_raw <= kSetLifecycleMax; ++state_raw) {
    const auto state = static_cast<SetLifecycle>(state_raw);
    std::string row;
    for (std::uint8_t event_raw = kSetEventMin; event_raw <= kSetEventMax; ++event_raw) {
      const auto event = static_cast<SetEvent>(event_raw);
      row.push_back(encode_set_action(set_transition(state, event)));
    }
    const std::string expected = kExpectedSetRows[state_raw - 1];
    MPF_CHECK_MSG(row == expected, std::string(to_string(state)) + " expected " + expected +
                                       " got " + row);
  }
  // Out-of-domain enumerators are rejected rather than reinterpreted.
  MPF_CHECK_EQ(set_transition(static_cast<SetLifecycle>(0), SetEvent::PUBLISH),
               SetTransitionAction::REJECT);
  MPF_CHECK_EQ(set_transition(static_cast<SetLifecycle>(11), SetEvent::PUBLISH),
               SetTransitionAction::REJECT);
  MPF_CHECK_EQ(set_transition(SetLifecycle::ACTIVE, static_cast<SetEvent>(0)),
               SetTransitionAction::REJECT);
  MPF_CHECK_EQ(set_transition(SetLifecycle::ACTIVE, static_cast<SetEvent>(19)),
               SetTransitionAction::REJECT);
}

MPF_TEST(member_transition_table_is_exhaustively_correct) {
  for (std::uint8_t state_raw = kMemberLifecycleMin; state_raw <= kMemberLifecycleMax;
       ++state_raw) {
    const auto state = static_cast<MemberLifecycle>(state_raw);
    std::string row;
    for (std::uint8_t event_raw = kMemberEventMin; event_raw <= kMemberEventMax; ++event_raw) {
      const auto event = static_cast<MemberEvent>(event_raw);
      const auto next = member_transition(state, event);
      if (!next.has_value()) {
        row.push_back('N');
        continue;
      }
      switch (*next) {
        case MemberLifecycle::PENDING: row.push_back('P'); break;
        case MemberLifecycle::CURRENT: row.push_back('C'); break;
        case MemberLifecycle::REVALIDATION_REQUIRED: row.push_back('R'); break;
        case MemberLifecycle::UNUSABLE: row.push_back('U'); break;
        case MemberLifecycle::WITHDRAWN: row.push_back('W'); break;
        case MemberLifecycle::SUPERSEDED: row.push_back('S'); break;
        case MemberLifecycle::RETIRED: row.push_back('T'); break;
      }
    }
    const std::string expected = kExpectedMemberRows[state_raw - 1];
    MPF_CHECK_MSG(row == expected, std::string(to_string(state)) + " expected " + expected +
                                       " got " + row);
  }
  MPF_CHECK(!member_transition(static_cast<MemberLifecycle>(0), MemberEvent::ADMITTED).has_value());
  MPF_CHECK(!member_transition(static_cast<MemberLifecycle>(8), MemberEvent::ADMITTED).has_value());
  MPF_CHECK(!member_transition(MemberLifecycle::CURRENT, static_cast<MemberEvent>(0)).has_value());
  MPF_CHECK(!member_transition(MemberLifecycle::CURRENT, static_cast<MemberEvent>(10)).has_value());
}

MPF_TEST(published_lifecycle_derivation_is_exhaustive) {
  // Every combination of usable members, minimum requirement and administrative
  // enablement, including the zero-minimum "no requirement" case.
  for (std::uint64_t minimum = 0; minimum <= 4; ++minimum) {
    for (std::uint64_t usable = 0; usable <= 4; ++usable) {
      const SetLifecycle enabled = derive_published_lifecycle(usable, minimum, true);
      SetLifecycle expected;
      if (usable >= minimum) {
        expected = SetLifecycle::ACTIVE;
      } else if (usable >= 1) {
        expected = SetLifecycle::DEGRADED;
      } else {
        expected = SetLifecycle::EXHAUSTED;
      }
      MPF_CHECK_MSG(enabled == expected,
                    "usable=" + std::to_string(usable) + " minimum=" + std::to_string(minimum));
      MPF_CHECK_EQ(derive_published_lifecycle(usable, minimum, false),
                   SetLifecycle::ADMIN_DISABLED);
    }
  }
  // Zero minimum with zero usable members is ACTIVE: there is no requirement to
  // violate.
  MPF_CHECK_EQ(derive_published_lifecycle(0, 0, true), SetLifecycle::ACTIVE);
}

MPF_TEST(route_readiness_covers_every_lifecycle_and_currentness) {
  const std::vector<std::pair<SetLifecycle, RouteReadiness>> current_expectations = {
      {SetLifecycle::DECLARED, RouteReadiness::NOT_PUBLISHED},
      {SetLifecycle::ACTIVE, RouteReadiness::READY},
      {SetLifecycle::DEGRADED, RouteReadiness::DEGRADED_BUT_READY},
      {SetLifecycle::EXHAUSTED, RouteReadiness::INSUFFICIENT_MEMBERS},
      {SetLifecycle::ADMIN_DISABLED, RouteReadiness::ADMIN_DISABLED},
      {SetLifecycle::WITHDRAWING, RouteReadiness::WITHDRAWN},
      {SetLifecycle::WITHDRAWN, RouteReadiness::WITHDRAWN},
      {SetLifecycle::SUPERSEDED, RouteReadiness::SUPERSEDED},
      {SetLifecycle::REVOKED, RouteReadiness::REVOKED},
      {SetLifecycle::RETIRED, RouteReadiness::RETIRED},
  };
  for (const auto& entry : current_expectations) {
    MPF_CHECK_MSG(route_readiness(entry.first, SetCurrentness::CURRENT) == entry.second,
                  std::string(to_string(entry.first)));
    const RouteReadiness stale = route_readiness(entry.first, SetCurrentness::REVALIDATION_REQUIRED);
    switch (entry.first) {
      case SetLifecycle::ACTIVE:
      case SetLifecycle::DEGRADED:
      case SetLifecycle::EXHAUSTED:
        MPF_CHECK_EQ(stale, RouteReadiness::REVALIDATION_REQUIRED);
        break;
      default:
        // Terminal and pre-publication states are unaffected by currentness.
        MPF_CHECK_EQ(stale, entry.second);
        break;
    }
  }
}

MPF_TEST(enumerators_round_trip_through_text) {
  for (std::uint8_t raw = kSetLifecycleMin; raw <= kSetLifecycleMax; ++raw) {
    const auto value = static_cast<SetLifecycle>(raw);
    const auto parsed = parse_set_lifecycle(to_string(value));
    MPF_REQUIRE(parsed.has_value());
    MPF_CHECK(*parsed == value);
    MPF_CHECK(valid_set_lifecycle(raw));
  }
  for (std::uint8_t raw = kMemberLifecycleMin; raw <= kMemberLifecycleMax; ++raw) {
    const auto value = static_cast<MemberLifecycle>(raw);
    MPF_REQUIRE(parse_member_lifecycle(to_string(value)).has_value());
    MPF_CHECK(*parse_member_lifecycle(to_string(value)) == value);
  }
  for (std::uint8_t raw = kMemberCurrentnessMin; raw <= kMemberCurrentnessMax; ++raw) {
    const auto value = static_cast<MemberCurrentness>(raw);
    MPF_REQUIRE(parse_member_currentness(to_string(value)).has_value());
    MPF_CHECK(*parse_member_currentness(to_string(value)) == value);
  }
  for (std::uint8_t raw = kRouteReadinessMin; raw <= kRouteReadinessMax; ++raw) {
    const auto value = static_cast<RouteReadiness>(raw);
    MPF_REQUIRE(parse_route_readiness(to_string(value)).has_value());
    MPF_CHECK(*parse_route_readiness(to_string(value)) == value);
  }
  for (std::uint8_t raw = kSetCurrentnessMin; raw <= kSetCurrentnessMax; ++raw) {
    const auto value = static_cast<SetCurrentness>(raw);
    MPF_REQUIRE(parse_set_currentness(to_string(value)).has_value());
    MPF_CHECK(*parse_set_currentness(to_string(value)) == value);
  }
  MPF_CHECK(!parse_set_lifecycle("NOT_A_STATE").has_value());
  MPF_CHECK(!parse_member_lifecycle("").has_value());
  MPF_CHECK(!parse_route_readiness("<invalid-route-readiness>").has_value());
}

MPF_TEST(lifecycle_codes_are_frozen) {
  // The numeric enumerator values are part of the persistence and wire contract.
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::DECLARED), std::uint8_t{1});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::ACTIVE), std::uint8_t{2});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::DEGRADED), std::uint8_t{3});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::EXHAUSTED), std::uint8_t{4});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::ADMIN_DISABLED), std::uint8_t{5});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::WITHDRAWING), std::uint8_t{6});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::WITHDRAWN), std::uint8_t{7});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::SUPERSEDED), std::uint8_t{8});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::REVOKED), std::uint8_t{9});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(SetLifecycle::RETIRED), std::uint8_t{10});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(RouteReadiness::READY), std::uint8_t{1});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(PathAuthorityState::AUTHORIZED), std::uint8_t{1});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(PathAuthorityState::RETIRED), std::uint8_t{7});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(RevocationReason::ADMINISTRATIVE), std::uint8_t{1});
  MPF_CHECK_EQ(static_cast<std::uint8_t>(RevocationReason::OPERATOR_REQUEST), std::uint8_t{5});
}

MPF_TEST(path_authority_classification_preserves_every_cause) {
  const PathId path = PathId::require("classification-path");
  const PathAuthorityGeneration bound = PathAuthorityGeneration::require(7);
  PathAuthorityView view;
  view.path = path;

  MPF_CHECK_EQ(classify_path_authority(std::nullopt, bound, false),
               MemberCurrentness::PATH_AUTHORITY_UNKNOWN);

  view.generation = PathAuthorityGeneration::require(8);
  view.state = PathAuthorityState::AUTHORIZED;
  // A generation mismatch wins over an otherwise usable state: a historical
  // AUTHORIZED result never counts after its generation changed.
  MPF_CHECK_EQ(classify_path_authority(view, bound, true),
               MemberCurrentness::STALE_PATH_AUTHORITY);

  view.generation = bound;
  view.state = PathAuthorityState::AUTHORIZED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, false), MemberCurrentness::CURRENT);

  view.state = PathAuthorityState::CONDITIONALLY_AUTHORIZED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, false),
               MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED);
  MPF_CHECK_EQ(classify_path_authority(view, bound, true), MemberCurrentness::CURRENT);

  view.state = PathAuthorityState::REVALIDATION_REQUIRED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, true),
               MemberCurrentness::PATH_REVALIDATION_REQUIRED);
  view.state = PathAuthorityState::REJECTED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, true), MemberCurrentness::PATH_REJECTED);
  view.state = PathAuthorityState::REVOKED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, true), MemberCurrentness::PATH_REVOKED);
  view.state = PathAuthorityState::STALE;
  MPF_CHECK_EQ(classify_path_authority(view, bound, true), MemberCurrentness::PATH_STALE);
  view.state = PathAuthorityState::RETIRED;
  MPF_CHECK_EQ(classify_path_authority(view, bound, true), MemberCurrentness::PATH_RETIRED);
}

MPF_TEST(member_usability_requires_both_axes_current) {
  MPF_CHECK(member_is_usable(MemberLifecycle::CURRENT, MemberCurrentness::CURRENT));
  for (std::uint8_t raw = kMemberLifecycleMin; raw <= kMemberLifecycleMax; ++raw) {
    const auto lifecycle = static_cast<MemberLifecycle>(raw);
    for (std::uint8_t other = kMemberCurrentnessMin; other <= kMemberCurrentnessMax; ++other) {
      const auto currentness = static_cast<MemberCurrentness>(other);
      const bool expected =
          lifecycle == MemberLifecycle::CURRENT && currentness == MemberCurrentness::CURRENT;
      MPF_CHECK_EQ(member_is_usable(lifecycle, currentness), expected);
    }
  }
}
