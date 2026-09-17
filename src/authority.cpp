#include "multipath_fabric/authority.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {

// ---------------------------------------------------------------------------
// AuthorityScope
// ---------------------------------------------------------------------------

bool AuthorityScope::well_formed() const noexcept {
  return fabric.valid() && name_space.valid();
}

bool AuthorityScope::covers_namespace(const FabricId& fabric_id,
                                          const MultipathNamespace& namespace_id) const noexcept {
  if (!well_formed()) {
    return false;
  }
  if (!set_ids.empty()) {
    return false;
  }
  return fabric == fabric_id && name_space == namespace_id;
}

bool AuthorityScope::covers(const FabricId& fabric_id, const MultipathNamespace& namespace_id,
                            const MultipathSetId& set_id) const noexcept {
  if (!well_formed() || !set_id.valid()) {
    return false;
  }
  if (!(fabric == fabric_id) || !(name_space == namespace_id)) {
    return false;
  }
  if (set_ids.empty()) {
    return true;
  }
  return std::find(set_ids.begin(), set_ids.end(), set_id) != set_ids.end();
}

std::string AuthorityScope::render() const {
  std::ostringstream stream;
  stream << (fabric.valid() ? fabric.view() : std::string_view("<unset>")) << '/'
         << (name_space.valid() ? name_space.view() : std::string_view("<unset>"));
  if (set_ids.empty()) {
    stream << " sets=*";
  } else {
    stream << " sets=";
    std::vector<MultipathSetId> sorted = set_ids;
    std::sort(sorted.begin(), sorted.end());
    for (std::size_t i = 0; i < sorted.size(); ++i) {
      if (i != 0) {
        stream << ',';
      }
      stream << sorted[i].view();
    }
  }
  return stream.str();
}

// ---------------------------------------------------------------------------
// PublisherRegistration / FenceRecord
// ---------------------------------------------------------------------------

std::string PublisherRegistration::render() const {
  std::ostringstream stream;
  stream << "publisher=" << publisher.view() << " boot=" << worker_boot.view()
         << " epoch=" << epoch.value() << " authority_gen=" << authority_generation.value()
         << " session=" << session.view() << " scope=" << scope.render();
  return stream.str();
}

std::string FenceRecord::render() const {
  std::ostringstream stream;
  stream << "publisher=" << publisher.view() << " boot=" << worker_boot.view()
         << " epoch=" << epoch.value() << " cause=" << cause;
  return stream.str();
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

std::string_view to_string(RevocationReason reason) noexcept {
  switch (reason) {
    case RevocationReason::ADMINISTRATIVE: return "ADMINISTRATIVE";
    case RevocationReason::SECURITY: return "SECURITY";
    case RevocationReason::POLICY_VIOLATION: return "POLICY_VIOLATION";
    case RevocationReason::AUTHORITY_REVOKED: return "AUTHORITY_REVOKED";
    case RevocationReason::OPERATOR_REQUEST: return "OPERATOR_REQUEST";
  }
  return "<invalid-revocation-reason>";
}

std::optional<RevocationReason> parse_revocation_reason(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 5; ++raw) {
    const auto candidate = static_cast<RevocationReason>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool valid_revocation_reason(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 5; }

std::string RevocationRecord::render() const {
  std::ostringstream stream;
  stream << "set=" << set_id.view() << " generation=" << generation.value()
         << " authority_gen=" << authority_generation.value() << " epoch=" << epoch.value()
         << " publisher=" << publisher.view() << " reason=" << to_string(reason);
  if (!detail.empty()) {
    stream << " detail=\"" << detail << "\"";
  }
  return stream.str();
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

std::string_view to_string(MembershipCause cause) noexcept {
  switch (cause) {
    case MembershipCause::DECLARED: return "DECLARED";
    case MembershipCause::MEMBER_ADDED: return "MEMBER_ADDED";
    case MembershipCause::MEMBER_REVALIDATED: return "MEMBER_REVALIDATED";
    case MembershipCause::MEMBER_REPLACED: return "MEMBER_REPLACED";
    case MembershipCause::MEMBER_REMOVED: return "MEMBER_REMOVED";
    case MembershipCause::PATH_INVALIDATED: return "PATH_INVALIDATED";
    case MembershipCause::MINIMUM_CHANGED: return "MINIMUM_CHANGED";
    case MembershipCause::POLICY_CHANGED: return "POLICY_CHANGED";
    case MembershipCause::ADMIN_ENABLED: return "ADMIN_ENABLED";
    case MembershipCause::ADMIN_DISABLED: return "ADMIN_DISABLED";
    case MembershipCause::SET_PUBLISHED: return "SET_PUBLISHED";
    case MembershipCause::SET_REVALIDATED: return "SET_REVALIDATED";
    case MembershipCause::SET_WITHDRAWN: return "SET_WITHDRAWN";
    case MembershipCause::SET_SUPERSEDED: return "SET_SUPERSEDED";
    case MembershipCause::SET_REVOKED: return "SET_REVOKED";
    case MembershipCause::SET_RETIRED: return "SET_RETIRED";
    case MembershipCause::EPOCH_ADVANCE: return "EPOCH_ADVANCE";
    case MembershipCause::RECOVERED: return "RECOVERED";
  }
  return "<invalid-membership-cause>";
}

bool valid_membership_cause(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 18; }

std::string MembershipProvenance::render() const {
  std::ostringstream stream;
  stream << "publisher=" << publisher.view() << " boot=" << worker_boot.view()
         << " epoch=" << epoch.value() << " attempt=" << attempt.view()
         << " set_gen=" << set_generation.value() << " cause=" << to_string(cause);
  return stream.str();
}

// ---------------------------------------------------------------------------
// MutationContext
// ---------------------------------------------------------------------------

bool MutationContext::has_caller_identity() const noexcept {
  return epoch.valid() && publisher.valid() && worker_boot.valid() && session.valid() &&
         attempt.valid();
}

std::string MutationContext::render() const {
  std::ostringstream stream;
  stream << "epoch=" << (epoch.valid() ? std::to_string(epoch.value()) : std::string("<unset>"))
         << " publisher=" << (publisher.valid() ? publisher.str() : std::string("<unset>"))
         << " boot=" << (worker_boot.valid() ? worker_boot.str() : std::string("<unset>"))
         << " session=" << (session.valid() ? session.str() : std::string("<unset>"))
         << " attempt=" << (attempt.valid() ? attempt.str() : std::string("<unset>"));
  if (expected_set_generation.has_value()) {
    stream << " expected_set_gen=" << expected_set_generation->value();
  }
  if (expected_member_generation.has_value()) {
    stream << " expected_member_gen=" << expected_member_generation->value();
  }
  return stream.str();
}

// ---------------------------------------------------------------------------
// AuthorityDescription
// ---------------------------------------------------------------------------

std::string AuthorityDescription::render() const {
  std::ostringstream stream;
  stream << "epoch=" << epoch.value() << " authority_gen=" << authority_generation.value()
         << " registrations=" << registrations.size() << " fences=" << fence_records.size();
  for (const auto& registration : registrations) {
    stream << "\n  registration " << registration.render();
  }
  for (const auto& fence : fence_records) {
    stream << "\n  fence " << fence.render();
  }
  return stream.str();
}

}  // namespace multipath_fabric
