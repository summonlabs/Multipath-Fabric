#include "multipath_fabric/outcome.hpp"

#include <sstream>

namespace multipath_fabric {

std::string_view to_string(OutcomeCode code) noexcept {
  switch (code) {
    case OutcomeCode::OK: return "OK";
    case OutcomeCode::CREATED: return "CREATED";
    case OutcomeCode::UPDATED: return "UPDATED";
    case OutcomeCode::IDEMPOTENT: return "IDEMPOTENT";
    case OutcomeCode::MEMBER_ADDED: return "MEMBER_ADDED";
    case OutcomeCode::MEMBER_REMOVED: return "MEMBER_REMOVED";
    case OutcomeCode::MEMBER_REPLACED: return "MEMBER_REPLACED";
    case OutcomeCode::MEMBER_REVALIDATED: return "MEMBER_REVALIDATED";
    case OutcomeCode::SET_REVALIDATED: return "SET_REVALIDATED";
    case OutcomeCode::SET_PUBLISHED: return "SET_PUBLISHED";
    case OutcomeCode::SET_DEGRADED: return "SET_DEGRADED";
    case OutcomeCode::SET_EXHAUSTED: return "SET_EXHAUSTED";
    case OutcomeCode::SET_ACTIVE: return "SET_ACTIVE";
    case OutcomeCode::SET_WITHDRAWING: return "SET_WITHDRAWING";
    case OutcomeCode::SET_WITHDRAWN: return "SET_WITHDRAWN";
    case OutcomeCode::SET_SUPERSEDED: return "SET_SUPERSEDED";
    case OutcomeCode::SET_REVOKED: return "SET_REVOKED";
    case OutcomeCode::SET_RETIRED: return "SET_RETIRED";
    case OutcomeCode::PUBLISHER_REGISTERED: return "PUBLISHER_REGISTERED";
    case OutcomeCode::PUBLISHER_UNREGISTERED: return "PUBLISHER_UNREGISTERED";
    case OutcomeCode::WORKER_FENCED: return "WORKER_FENCED";
    case OutcomeCode::EPOCH_ADVANCED: return "EPOCH_ADVANCED";
    case OutcomeCode::PATH_INVALIDATED: return "PATH_INVALIDATED";
    case OutcomeCode::MEMBER_WITHDRAWN: return "MEMBER_WITHDRAWN";
    case OutcomeCode::RECOVERED: return "RECOVERED";
    case OutcomeCode::STORE_SAVED: return "STORE_SAVED";
    case OutcomeCode::MEMBER_REVALIDATION_NEGATIVE: return "MEMBER_REVALIDATION_NEGATIVE";
    case OutcomeCode::SET_REVALIDATION_INCOMPLETE: return "SET_REVALIDATION_INCOMPLETE";

    case OutcomeCode::MALFORMED_REQUEST: return "MALFORMED_REQUEST";
    case OutcomeCode::UNAUTHORIZED_CALLER: return "UNAUTHORIZED_CALLER";
    case OutcomeCode::UNKNOWN_PUBLISHER: return "UNKNOWN_PUBLISHER";
    case OutcomeCode::STALE_EPOCH: return "STALE_EPOCH";
    case OutcomeCode::STALE_WORKER: return "STALE_WORKER";
    case OutcomeCode::UNAUTHORIZED_SCOPE: return "UNAUTHORIZED_SCOPE";
    case OutcomeCode::ATTEMPT_CONFLICT: return "ATTEMPT_CONFLICT";
    case OutcomeCode::SET_NOT_FOUND: return "SET_NOT_FOUND";
    case OutcomeCode::MEMBER_NOT_FOUND: return "MEMBER_NOT_FOUND";
    case OutcomeCode::SET_KEY_CONFLICT: return "SET_KEY_CONFLICT";
    case OutcomeCode::STALE_SET_GENERATION: return "STALE_SET_GENERATION";
    case OutcomeCode::STALE_MEMBER_GENERATION: return "STALE_MEMBER_GENERATION";
    case OutcomeCode::INVALID_LIFECYCLE_TRANSITION: return "INVALID_LIFECYCLE_TRANSITION";
    case OutcomeCode::REVOKED: return "REVOKED";
    case OutcomeCode::RETIRED: return "RETIRED";
    case OutcomeCode::WITHDRAWN: return "WITHDRAWN";
    case OutcomeCode::SUPERSEDED: return "SUPERSEDED";
    case OutcomeCode::STALE_PATH_AUTHORITY: return "STALE_PATH_AUTHORITY";
    case OutcomeCode::PATH_NOT_USABLE: return "PATH_NOT_USABLE";
    case OutcomeCode::DUPLICATE_MEMBER: return "DUPLICATE_MEMBER";
    case OutcomeCode::INSUFFICIENT_MEMBERS: return "INSUFFICIENT_MEMBERS";
    case OutcomeCode::RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case OutcomeCode::GENERATION_OVERFLOW: return "GENERATION_OVERFLOW";
    case OutcomeCode::STALE_REVALIDATION: return "STALE_REVALIDATION";
    case OutcomeCode::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case OutcomeCode::PATH_AUTHORITY_UNKNOWN: return "PATH_AUTHORITY_UNKNOWN";
    case OutcomeCode::SET_ADMIN_DISABLED: return "SET_ADMIN_DISABLED";
    case OutcomeCode::INVALID_THRESHOLD: return "INVALID_THRESHOLD";
    case OutcomeCode::BATCH_ABORTED: return "BATCH_ABORTED";
    case OutcomeCode::UNSUPPORTED_OPERATION: return "UNSUPPORTED_OPERATION";
    case OutcomeCode::FRAMING_ERROR: return "FRAMING_ERROR";
    case OutcomeCode::INTEGRITY_ERROR: return "INTEGRITY_ERROR";
    case OutcomeCode::UNSUPPORTED_WIRE_VERSION: return "UNSUPPORTED_WIRE_VERSION";
    case OutcomeCode::PROTOCOL_ERROR: return "PROTOCOL_ERROR";
    case OutcomeCode::SESSION_TIMEOUT: return "SESSION_TIMEOUT";
    case OutcomeCode::SESSION_LIMIT: return "SESSION_LIMIT";
    case OutcomeCode::STORE_CORRUPT: return "STORE_CORRUPT";
    case OutcomeCode::STORE_VERSION_UNSUPPORTED: return "STORE_VERSION_UNSUPPORTED";
    case OutcomeCode::STORE_IO_ERROR: return "STORE_IO_ERROR";
    case OutcomeCode::STORE_DUPLICATE_SET: return "STORE_DUPLICATE_SET";
    case OutcomeCode::STORE_DUPLICATE_MEMBER: return "STORE_DUPLICATE_MEMBER";
    case OutcomeCode::STORE_DANGLING_MEMBER: return "STORE_DANGLING_MEMBER";
    case OutcomeCode::DETACHED_AUTHORITY: return "DETACHED_AUTHORITY";
    case OutcomeCode::INTERNAL_ERROR: return "INTERNAL_ERROR";
  }
  return "<unknown-outcome>";
}

std::string_view to_string(RejectionStage stage) noexcept {
  switch (stage) {
    case RejectionStage::NONE: return "NONE";
    case RejectionStage::DECODE: return "DECODE";
    case RejectionStage::CALLER_IDENTITY: return "CALLER_IDENTITY";
    case RejectionStage::EPOCH: return "EPOCH";
    case RejectionStage::WORKER_AUTHORITY: return "WORKER_AUTHORITY";
    case RejectionStage::SCOPE: return "SCOPE";
    case RejectionStage::ATTEMPT: return "ATTEMPT";
    case RejectionStage::SET_STATE: return "SET_STATE";
    case RejectionStage::GENERATION: return "GENERATION";
    case RejectionStage::PATH_AUTHORITY: return "PATH_AUTHORITY";
    case RejectionStage::RESOURCE_LIMIT: return "RESOURCE_LIMIT";
    case RejectionStage::SEMANTIC: return "SEMANTIC";
    case RejectionStage::COMMIT: return "COMMIT";
  }
  return "<unknown-stage>";
}

std::optional<OutcomeCode> parse_outcome_code(std::string_view text) noexcept {
  for (std::uint16_t raw = 0; raw <= 200; ++raw) {
    if (!valid_outcome_code(raw)) {
      continue;
    }
    const auto candidate = static_cast<OutcomeCode>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool valid_outcome_code(std::uint16_t raw) noexcept {
  if (raw <= 27) {
    return true;
  }
  return raw >= 100 && raw <= 143;
}

bool outcome_is_success(OutcomeCode code) noexcept {
  return static_cast<std::uint16_t>(code) < 100;
}

RejectionStage stage_of(OutcomeCode code) noexcept {
  switch (code) {
    case OutcomeCode::MALFORMED_REQUEST:
      return RejectionStage::DECODE;
    case OutcomeCode::UNAUTHORIZED_CALLER:
      return RejectionStage::CALLER_IDENTITY;
    case OutcomeCode::STALE_EPOCH:
      return RejectionStage::EPOCH;
    case OutcomeCode::UNKNOWN_PUBLISHER:
    case OutcomeCode::STALE_WORKER:
    case OutcomeCode::DETACHED_AUTHORITY:
      return RejectionStage::WORKER_AUTHORITY;
    case OutcomeCode::UNAUTHORIZED_SCOPE:
      return RejectionStage::SCOPE;
    case OutcomeCode::ATTEMPT_CONFLICT:
      return RejectionStage::ATTEMPT;
    case OutcomeCode::SET_NOT_FOUND:
    case OutcomeCode::MEMBER_NOT_FOUND:
    case OutcomeCode::SET_KEY_CONFLICT:
    case OutcomeCode::REVOKED:
    case OutcomeCode::RETIRED:
    case OutcomeCode::WITHDRAWN:
    case OutcomeCode::SUPERSEDED:
    case OutcomeCode::INVALID_LIFECYCLE_TRANSITION:
      return RejectionStage::SET_STATE;
    case OutcomeCode::STALE_SET_GENERATION:
    case OutcomeCode::STALE_MEMBER_GENERATION:
    case OutcomeCode::GENERATION_OVERFLOW:
      return RejectionStage::GENERATION;
    case OutcomeCode::STALE_PATH_AUTHORITY:
    case OutcomeCode::PATH_NOT_USABLE:
    case OutcomeCode::PATH_AUTHORITY_UNKNOWN:
    case OutcomeCode::STALE_REVALIDATION:
      return RejectionStage::PATH_AUTHORITY;
    case OutcomeCode::RESOURCE_LIMIT:
    case OutcomeCode::SESSION_LIMIT:
      return RejectionStage::RESOURCE_LIMIT;
    case OutcomeCode::DUPLICATE_MEMBER:
    case OutcomeCode::INSUFFICIENT_MEMBERS:
    case OutcomeCode::INVALID_THRESHOLD:
    case OutcomeCode::REVALIDATION_REQUIRED:
    case OutcomeCode::SET_ADMIN_DISABLED:
    case OutcomeCode::BATCH_ABORTED:
    case OutcomeCode::UNSUPPORTED_OPERATION:
      return RejectionStage::SEMANTIC;
    case OutcomeCode::STORE_IO_ERROR:
    case OutcomeCode::STORE_CORRUPT:
    case OutcomeCode::STORE_VERSION_UNSUPPORTED:
    case OutcomeCode::STORE_DUPLICATE_SET:
    case OutcomeCode::STORE_DUPLICATE_MEMBER:
    case OutcomeCode::STORE_DANGLING_MEMBER:
    case OutcomeCode::INTERNAL_ERROR:
      return RejectionStage::COMMIT;
    case OutcomeCode::FRAMING_ERROR:
    case OutcomeCode::INTEGRITY_ERROR:
    case OutcomeCode::UNSUPPORTED_WIRE_VERSION:
    case OutcomeCode::PROTOCOL_ERROR:
    case OutcomeCode::SESSION_TIMEOUT:
      return RejectionStage::DECODE;
    default:
      return RejectionStage::NONE;
  }
}

FabricOutcome make_outcome(OutcomeCode code, std::string detail_value) {
  FabricOutcome outcome;
  outcome.code = code;
  outcome.stage = outcome_is_success(code) ? RejectionStage::NONE : stage_of(code);
  outcome.detail = std::move(detail_value);
  return outcome;
}

FabricOutcome make_rejection(OutcomeCode code, std::string detail_value) {
  return make_outcome(code, std::move(detail_value));
}

std::string FabricOutcome::render() const {
  std::ostringstream stream;
  stream << to_string(code);
  if (!outcome_is_success(code)) {
    stream << " stage=" << to_string(stage);
  }
  if (set_id.has_value()) {
    stream << " set=" << set_id->view();
  }
  if (member_id.has_value()) {
    stream << " member=" << member_id->view();
  }
  if (path_id.has_value()) {
    stream << " path=" << path_id->view();
  }
  if (set_generation.has_value()) {
    stream << " set_gen=" << set_generation->value();
  }
  if (membership_generation.has_value()) {
    stream << " membership_gen=" << membership_generation->value();
  }
  if (member_generation.has_value()) {
    stream << " member_gen=" << member_generation->value();
  }
  if (authority_generation.has_value()) {
    stream << " authority_gen=" << authority_generation->value();
  }
  if (lifecycle.has_value()) {
    stream << " lifecycle=" << to_string(*lifecycle);
  }
  if (currentness.has_value()) {
    stream << " currentness=" << to_string(*currentness);
  }
  if (usable_members.has_value()) {
    stream << " usable=" << *usable_members;
  }
  if (minimum_usable_members.has_value()) {
    stream << " minimum=" << *minimum_usable_members;
  }
  if (digest.has_value()) {
    stream << " digest=" << digest->to_hex();
  }
  if (!detail.empty()) {
    stream << " detail=\"" << detail << "\"";
  }
  return stream.str();
}

}  // namespace multipath_fabric
