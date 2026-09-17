// Mutation authority, scope, fencing and epoch binding.
//
// Being connected is not authority. Being a known publisher is not authority.
// Having a durable record is not authority. Every mutation binds the current
// coordinator epoch, the publisher, the worker boot incarnation, the authority
// scope, the expected generations and a mutation attempt id.
//
// AUTHORITY MODEL
// ---------------
// Exactly one coordinator owns mutation authority for a Multipath Fabric
// deployment. Multipath Fabric does not implement consensus and does not claim
// split-brain prevention between isolated coordinators. What it does implement
// is mandatory stale-epoch and stale-worker rejection: after an epoch advance
// or a coordinator restart, no request carrying the previous epoch, the
// previous worker boot or a fenced session is ever accepted.
#ifndef MULTIPATH_FABRIC_AUTHORITY_HPP
#define MULTIPATH_FABRIC_AUTHORITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "multipath_fabric/ids.hpp"

namespace multipath_fabric {

// ---------------------------------------------------------------------------
// Authority scope
// ---------------------------------------------------------------------------

// Default deny. A registration must name a fabric and a multipath namespace.
// An empty set_ids vector authorizes every set inside that fabric/namespace
// pair; a non-empty vector authorizes only the listed set ids.
struct AuthorityScope {
  FabricId fabric;
  MultipathNamespace name_space;
  std::vector<MultipathSetId> set_ids;

  [[nodiscard]] bool well_formed() const noexcept;
  // Namespace-level coverage, used when a set identity does not exist yet
  // (create_set). A set-restricted scope never covers namespace-level
  // operations because it cannot identify the set it would authorize.
  [[nodiscard]] bool covers_namespace(const FabricId& fabric_id,
                                      const MultipathNamespace& namespace_id) const noexcept;
  [[nodiscard]] bool covers(const FabricId& fabric_id, const MultipathNamespace& namespace_id,
                            const MultipathSetId& set_id) const noexcept;
  [[nodiscard]] bool covers_all_in_scope() const noexcept { return set_ids.empty(); }
  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Publisher registration
// ---------------------------------------------------------------------------

struct PublisherRegistration {
  PublisherId publisher;
  WorkerBootId worker_boot;
  AuthorityScope scope;
  CoordinatorEpoch epoch;
  MultipathAuthorityGeneration authority_generation;
  SessionId session;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Fencing
// ---------------------------------------------------------------------------

struct FenceRecord {
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  // Deterministic cause: SESSION_LOST, EXPLICIT, EPOCH_ADVANCE, SHUTDOWN,
  // SCOPE_REVOKED.
  std::string cause;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

enum class RevocationReason : std::uint8_t {
  ADMINISTRATIVE = 1,
  SECURITY = 2,
  POLICY_VIOLATION = 3,
  AUTHORITY_REVOKED = 4,
  OPERATOR_REQUEST = 5,
};

[[nodiscard]] std::string_view to_string(RevocationReason reason) noexcept;
[[nodiscard]] std::optional<RevocationReason> parse_revocation_reason(
    std::string_view text) noexcept;
[[nodiscard]] bool valid_revocation_reason(std::uint8_t raw) noexcept;

// Revocation is durable, idempotent, generation-bound and reason-coded. It is
// distinct from member failure, set degradation, path invalidation, publisher
// fencing and retirement.
struct RevocationRecord {
  MultipathSetId set_id;
  MultipathSetGeneration generation;
  MultipathAuthorityGeneration authority_generation;
  CoordinatorEpoch epoch;
  PublisherId publisher;
  RevocationReason reason = RevocationReason::ADMINISTRATIVE;
  std::string detail;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

// Why a membership fact exists and who established it.
enum class MembershipCause : std::uint8_t {
  DECLARED = 1,
  MEMBER_ADDED = 2,
  MEMBER_REVALIDATED = 3,
  MEMBER_REPLACED = 4,
  MEMBER_REMOVED = 5,
  PATH_INVALIDATED = 6,
  MINIMUM_CHANGED = 7,
  POLICY_CHANGED = 8,
  ADMIN_ENABLED = 9,
  ADMIN_DISABLED = 10,
  SET_PUBLISHED = 11,
  SET_REVALIDATED = 12,
  SET_WITHDRAWN = 13,
  SET_SUPERSEDED = 14,
  SET_REVOKED = 15,
  SET_RETIRED = 16,
  EPOCH_ADVANCE = 17,
  RECOVERED = 18,
};

[[nodiscard]] std::string_view to_string(MembershipCause cause) noexcept;
[[nodiscard]] bool valid_membership_cause(std::uint8_t raw) noexcept;

struct MembershipProvenance {
  PublisherId publisher;
  WorkerBootId worker_boot;
  CoordinatorEpoch epoch;
  MutationAttemptId attempt;
  MultipathSetGeneration set_generation;
  MembershipCause cause = MembershipCause::DECLARED;

  [[nodiscard]] std::string render() const;
};

// ---------------------------------------------------------------------------
// Mutation context
// ---------------------------------------------------------------------------

// The complete authority binding supplied with every mutation. A context with
// any missing element is malformed and is rejected at the CALLER_IDENTITY or
// DECODE stage before any state is consulted.
struct MutationContext {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  SessionId session;
  MutationAttemptId attempt;
  std::optional<MultipathSetGeneration> expected_set_generation;
  std::optional<MultipathMemberGeneration> expected_member_generation;

  [[nodiscard]] bool has_caller_identity() const noexcept;
  [[nodiscard]] std::string render() const;
};

// Scope descriptor for the authority registry, used by the CLI and by
// explanations that must answer "which publisher owns mutation authority".
struct AuthorityDescription {
  CoordinatorEpoch epoch;
  MultipathAuthorityGeneration authority_generation;
  std::vector<PublisherRegistration> registrations;
  std::vector<FenceRecord> fence_records;

  [[nodiscard]] std::string render() const;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_AUTHORITY_HPP
