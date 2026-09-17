// Structured operation outcomes.
//
// No Multipath Fabric mutation returns bool. Every mutation returns a
// FabricOutcome carrying an explicit code, the rejection stage that produced it
// (when it is a rejection), the resulting generations and a deterministic
// operator-facing detail string.
#ifndef MULTIPATH_FABRIC_OUTCOME_HPP
#define MULTIPATH_FABRIC_OUTCOME_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "multipath_fabric/detail/bytes.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"

namespace multipath_fabric {

// Explicit numeric values. These are part of the wire contract and are frozen:
// the test suite asserts each value literally.
enum class OutcomeCode : std::uint16_t {
  // -- success ---------------------------------------------------------------
  OK = 0,
  CREATED = 1,
  UPDATED = 2,
  IDEMPOTENT = 3,
  MEMBER_ADDED = 4,
  MEMBER_REMOVED = 5,
  MEMBER_REPLACED = 6,
  MEMBER_REVALIDATED = 7,
  SET_REVALIDATED = 8,
  SET_PUBLISHED = 9,
  SET_DEGRADED = 10,
  SET_EXHAUSTED = 11,
  SET_ACTIVE = 12,
  SET_WITHDRAWING = 13,
  SET_WITHDRAWN = 14,
  SET_SUPERSEDED = 15,
  SET_REVOKED = 16,
  SET_RETIRED = 17,
  PUBLISHER_REGISTERED = 18,
  PUBLISHER_UNREGISTERED = 19,
  WORKER_FENCED = 20,
  EPOCH_ADVANCED = 21,
  PATH_INVALIDATED = 22,
  MEMBER_WITHDRAWN = 23,
  RECOVERED = 24,
  STORE_SAVED = 25,
  // The evaluation completed but the member is still not usable. The cause is
  // carried in the outcome fields and detail; no rejection happened.
  MEMBER_REVALIDATION_NEGATIVE = 26,
  // The set evaluation completed but live currentness could not be fully
  // re-established (for example a member path had no Path Authority record).
  SET_REVALIDATION_INCOMPLETE = 27,

  // -- rejection -------------------------------------------------------------
  MALFORMED_REQUEST = 100,
  UNAUTHORIZED_CALLER = 101,
  UNKNOWN_PUBLISHER = 102,
  STALE_EPOCH = 103,
  STALE_WORKER = 104,
  UNAUTHORIZED_SCOPE = 105,
  ATTEMPT_CONFLICT = 106,
  SET_NOT_FOUND = 107,
  MEMBER_NOT_FOUND = 108,
  SET_KEY_CONFLICT = 109,
  STALE_SET_GENERATION = 110,
  STALE_MEMBER_GENERATION = 111,
  INVALID_LIFECYCLE_TRANSITION = 112,
  REVOKED = 113,
  RETIRED = 114,
  WITHDRAWN = 115,
  SUPERSEDED = 116,
  STALE_PATH_AUTHORITY = 117,
  PATH_NOT_USABLE = 118,
  DUPLICATE_MEMBER = 119,
  INSUFFICIENT_MEMBERS = 120,
  RESOURCE_LIMIT = 121,
  GENERATION_OVERFLOW = 122,
  STALE_REVALIDATION = 123,
  REVALIDATION_REQUIRED = 124,
  PATH_AUTHORITY_UNKNOWN = 125,
  SET_ADMIN_DISABLED = 126,
  INVALID_THRESHOLD = 127,
  BATCH_ABORTED = 128,
  UNSUPPORTED_OPERATION = 129,
  FRAMING_ERROR = 130,
  INTEGRITY_ERROR = 131,
  UNSUPPORTED_WIRE_VERSION = 132,
  PROTOCOL_ERROR = 133,
  SESSION_TIMEOUT = 134,
  SESSION_LIMIT = 135,
  STORE_CORRUPT = 136,
  STORE_VERSION_UNSUPPORTED = 137,
  STORE_IO_ERROR = 138,
  STORE_DUPLICATE_SET = 139,
  STORE_DUPLICATE_MEMBER = 140,
  STORE_DANGLING_MEMBER = 141,
  DETACHED_AUTHORITY = 142,
  INTERNAL_ERROR = 143,
};

// The fixed rejection precedence. Every rejection carries the stage that
// produced it so multi-failure inputs have a documented, testable answer.
//
// 1  DECODE             structural/framing validation of the request itself
// 2  CALLER_IDENTITY    caller identity present and well formed
// 3  EPOCH              governing coordinator epoch currency
// 4  WORKER_AUTHORITY   publisher/boot registration and fencing
// 5  SCOPE              authority scope over fabric/namespace/set ids
// 6  ATTEMPT            attempt-id classification (replay / conflict)
// 7  SET_STATE          set existence and lifecycle admissibility
// 8  GENERATION         expected set/member generation match
// 9  PATH_AUTHORITY     exact path authority binding checks
// 10 RESOURCE_LIMIT     configured capacity limits
// 11 SEMANTIC           semantic validation (duplicates, thresholds, sizes)
// 12 COMMIT             durable commit of an accepted mutation
//
// Note the deliberate placement of ATTEMPT before GENERATION. A replay of an
// already-committed mutation necessarily carries the pre-commit expected
// generation, so classifying attempts after the generation check would make
// exact replay recognition impossible. Every authority check (stages 2-5) still
// precedes attempt classification, so a stale replay cannot be accepted merely
// because its attempt id is known.
enum class RejectionStage : std::uint8_t {
  NONE = 0,
  DECODE = 1,
  CALLER_IDENTITY = 2,
  EPOCH = 3,
  WORKER_AUTHORITY = 4,
  SCOPE = 5,
  ATTEMPT = 6,
  SET_STATE = 7,
  GENERATION = 8,
  PATH_AUTHORITY = 9,
  RESOURCE_LIMIT = 10,
  SEMANTIC = 11,
  COMMIT = 12,
};

[[nodiscard]] std::string_view to_string(OutcomeCode code) noexcept;
[[nodiscard]] std::string_view to_string(RejectionStage stage) noexcept;
[[nodiscard]] std::optional<OutcomeCode> parse_outcome_code(std::string_view text) noexcept;
[[nodiscard]] bool outcome_is_success(OutcomeCode code) noexcept;
[[nodiscard]] RejectionStage stage_of(OutcomeCode code) noexcept;
[[nodiscard]] bool valid_outcome_code(std::uint16_t raw) noexcept;

struct FabricOutcome {
  OutcomeCode code = OutcomeCode::OK;
  RejectionStage stage = RejectionStage::NONE;
  // Deterministic, operator-facing explanation of the result. Contains no
  // timestamps, addresses or process-local diagnostics.
  std::string detail;

  std::optional<MultipathSetId> set_id;
  std::optional<MultipathMemberId> member_id;
  std::optional<PathId> path_id;
  std::optional<MultipathSetGeneration> set_generation;
  std::optional<MembershipGeneration> membership_generation;
  std::optional<MultipathMemberGeneration> member_generation;
  std::optional<MultipathAuthorityGeneration> authority_generation;
  std::optional<SetLifecycle> lifecycle;
  std::optional<SetCurrentness> currentness;
  std::optional<std::uint64_t> usable_members;
  std::optional<std::uint64_t> minimum_usable_members;
  std::optional<detail::Digest128> digest;

  [[nodiscard]] bool succeeded() const noexcept { return outcome_is_success(code); }

  // Stable single-line rendering used by the CLI and by tests.
  [[nodiscard]] std::string render() const;
};

// Convenience constructors used throughout the engine.
[[nodiscard]] FabricOutcome make_outcome(OutcomeCode code, std::string detail);
[[nodiscard]] FabricOutcome make_rejection(OutcomeCode code, std::string detail);

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_OUTCOME_HPP
