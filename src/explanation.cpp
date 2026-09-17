#include "engine_impl.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {
namespace {

[[nodiscard]] ExplanationReason member_reason(const detail::MemberRecord& member) {
  if (!member.admin_enabled) {
    return ExplanationReason::MEMBER_ADMIN_DISABLED;
  }
  switch (member.currentness) {
    case MemberCurrentness::CURRENT:
      if (member.lifecycle == MemberLifecycle::CURRENT) {
        return member.pending_revalidations > 0 ? ExplanationReason::MEMBER_PENDING_REVALIDATION
                                                : ExplanationReason::MEMBER_USABLE;
      }
      return ExplanationReason::MEMBER_LIFECYCLE_NOT_CURRENT;
    case MemberCurrentness::STALE_PATH_AUTHORITY:
      return ExplanationReason::MEMBER_PATH_AUTHORITY_GENERATION_STALE;
    case MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED:
      return ExplanationReason::MEMBER_PATH_CONDITIONALLY_NOT_PERMITTED;
    case MemberCurrentness::PATH_REVALIDATION_REQUIRED:
    case MemberCurrentness::PATH_STALE:
    case MemberCurrentness::PATH_REJECTED:
    case MemberCurrentness::PATH_REVOKED:
    case MemberCurrentness::PATH_RETIRED:
      return ExplanationReason::MEMBER_PATH_STATE_NOT_USABLE;
    case MemberCurrentness::PATH_AUTHORITY_UNKNOWN:
      return ExplanationReason::MEMBER_PATH_AUTHORITY_UNKNOWN;
    case MemberCurrentness::ADMIN_DISABLED:
      return ExplanationReason::MEMBER_ADMIN_DISABLED;
    case MemberCurrentness::SET_NOT_USABLE:
      return ExplanationReason::MEMBER_SET_NOT_USABLE;
    case MemberCurrentness::EPOCH_STALE:
      return ExplanationReason::MEMBER_EPOCH_STALE;
    case MemberCurrentness::AUTHORITY_FENCED:
      return ExplanationReason::MEMBER_AUTHORITY_FENCED;
    case MemberCurrentness::PENDING_EVALUATION:
      return ExplanationReason::MEMBER_PENDING_EVALUATION;
  }
  return ExplanationReason::MEMBER_LIFECYCLE_NOT_CURRENT;
}

}  // namespace

SetExplanation FabricEngine::Impl::make_explanation_locked(
    const detail::SetRecord& record,
    const std::map<PathId, std::optional<PathAuthorityView>>& observed) const {
  SetExplanation explanation;
  explanation.set_id = record.id;
  explanation.key = record.key;
  explanation.lifecycle = record.lifecycle;
  explanation.currentness = record.currentness;
  explanation.readiness = route_readiness(record.lifecycle, record.currentness);
  explanation.member_count = record.members.size();
  explanation.usable_member_count = record.usable_member_count;
  explanation.minimum_usable_members = record.minimum_usable_members;
  explanation.minimum_satisfied = record.usable_member_count >= record.minimum_usable_members;
  explanation.admin_enabled = record.admin_enabled;
  explanation.conditional_authority_permitted = record.conditional_authority_permitted;
  explanation.governing_epoch = record.governing_epoch;
  explanation.authority_generation = record.authority_generation;
  explanation.last_cause = record.provenance.cause;
  if (record.provenance.publisher.valid()) {
    explanation.last_mutating_publisher = record.provenance.publisher;
  }

  switch (record.lifecycle) {
    case SetLifecycle::DECLARED:
      explanation.reasons.push_back(ExplanationReason::SET_NOT_PUBLISHED);
      break;
    case SetLifecycle::ACTIVE:
      explanation.reasons.push_back(ExplanationReason::SET_PUBLISHED_AND_THRESHOLD_MET);
      break;
    case SetLifecycle::DEGRADED:
      explanation.reasons.push_back(ExplanationReason::SET_BELOW_MINIMUM);
      explanation.reasons.push_back(ExplanationReason::MINIMUM_MEMBERSHIP_UNSATISFIED);
      break;
    case SetLifecycle::EXHAUSTED:
      explanation.reasons.push_back(ExplanationReason::SET_ZERO_USABLE_MEMBERS);
      explanation.reasons.push_back(ExplanationReason::MINIMUM_MEMBERSHIP_UNSATISFIED);
      break;
    case SetLifecycle::ADMIN_DISABLED:
      explanation.reasons.push_back(ExplanationReason::SET_ADMIN_DISABLED);
      break;
    case SetLifecycle::WITHDRAWING:
    case SetLifecycle::WITHDRAWN:
      explanation.reasons.push_back(ExplanationReason::SET_WITHDRAWN);
      break;
    case SetLifecycle::SUPERSEDED:
      explanation.reasons.push_back(ExplanationReason::SET_SUPERSEDED);
      break;
    case SetLifecycle::REVOKED:
      explanation.reasons.push_back(ExplanationReason::SET_REVOKED);
      break;
    case SetLifecycle::RETIRED:
      explanation.reasons.push_back(ExplanationReason::SET_RETIRED);
      break;
  }
  if (record.currentness != SetCurrentness::CURRENT) {
    explanation.reasons.push_back(ExplanationReason::SET_CURRENTNESS_NOT_ESTABLISHED);
  }
  if (record.lifecycle == SetLifecycle::ACTIVE && !explanation.minimum_satisfied) {
    explanation.reasons.push_back(ExplanationReason::MINIMUM_MEMBERSHIP_UNSATISFIED);
  }

  explanation.members.reserve(record.members.size());
  for (const auto& entry : record.members) {
    const detail::MemberRecord& member = entry.second;
    MemberExplanation member_explanation;
    member_explanation.id = member.id;
    member_explanation.path_id = member.path_id;
    member_explanation.lifecycle = member.lifecycle;
    member_explanation.currentness = member.currentness;
    member_explanation.admin_enabled = member.admin_enabled;
    member_explanation.usable = member_inputs_usable(member);
    member_explanation.bound_authority_generation = member.bound_authority_generation;
    member_explanation.pending_revalidations = member.pending_revalidations;
    member_explanation.reason = member_reason(member);
    const auto view = observed.find(member.path_id);
    if (view != observed.end() && view->second.has_value()) {
      member_explanation.observed_authority_generation = view->second->generation;
      member_explanation.observed_authority_state = view->second->state;
    }
    explanation.members.push_back(std::move(member_explanation));
  }
  if (explanation.members.size() > config.limits.max_explanation_entries) {
    explanation.members.resize(static_cast<std::size_t>(config.limits.max_explanation_entries));
    explanation.truncated = true;
    explanation.reasons.push_back(ExplanationReason::EXPLANATION_TRUNCATED);
  }
  return explanation;
}

std::vector<RejectionStage> rejection_precedence() {
  return {RejectionStage::DECODE,          RejectionStage::CALLER_IDENTITY,
          RejectionStage::EPOCH,           RejectionStage::WORKER_AUTHORITY,
          RejectionStage::SCOPE,           RejectionStage::ATTEMPT,
          RejectionStage::SET_STATE,       RejectionStage::GENERATION,
          RejectionStage::PATH_AUTHORITY,  RejectionStage::RESOURCE_LIMIT,
          RejectionStage::SEMANTIC,        RejectionStage::COMMIT};
}

RejectionExplanation explain_rejection(const FabricOutcome& outcome) {
  RejectionExplanation explanation;
  explanation.code = outcome.code;
  explanation.stage = outcome.stage;
  explanation.detail = outcome.detail;
  explanation.precedence = 0;
  const std::vector<RejectionStage> stages = rejection_precedence();
  for (std::size_t i = 0; i < stages.size(); ++i) {
    if (stages[i] == outcome.stage) {
      explanation.precedence = static_cast<std::uint8_t>(i + 1);
      break;
    }
  }
  switch (outcome.code) {
    case OutcomeCode::STALE_EPOCH:
      explanation.guidance =
          "re-register with the governing coordinator epoch and retry under a new attempt id";
      break;
    case OutcomeCode::STALE_WORKER:
      explanation.guidance =
          "the worker boot is fenced permanently; start a fresh worker boot and register again";
      break;
    case OutcomeCode::UNKNOWN_PUBLISHER:
      explanation.guidance = "register the publisher and worker boot with an authority scope first";
      break;
    case OutcomeCode::UNAUTHORIZED_SCOPE:
      explanation.guidance =
          "the authority scope does not cover this fabric, namespace or set identity";
      break;
    case OutcomeCode::ATTEMPT_CONFLICT:
      explanation.guidance =
          "the attempt id was already used for a different semantic request; use a fresh attempt "
          "id";
      break;
    case OutcomeCode::STALE_SET_GENERATION:
    case OutcomeCode::STALE_MEMBER_GENERATION:
      explanation.guidance = "re-read the current generation and retry the mutation";
      break;
    case OutcomeCode::STALE_PATH_AUTHORITY:
      explanation.guidance =
          "revalidate the member against the current Path Authority generation";
      break;
    case OutcomeCode::STALE_REVALIDATION:
      explanation.guidance =
          "the member or set inputs changed while revalidation was in flight; begin a new "
          "revalidation";
      break;
    case OutcomeCode::DUPLICATE_MEMBER:
      explanation.guidance =
          "the exact PathId is already a live member of this set; remove or replace it explicitly";
      break;
    case OutcomeCode::INSUFFICIENT_MEMBERS:
      explanation.guidance = "add usable members or lower the minimum usable-member requirement";
      break;
    case OutcomeCode::RESOURCE_LIMIT:
      explanation.guidance = "a configured resource limit was reached; see Limits::describe()";
      break;
    case OutcomeCode::GENERATION_OVERFLOW:
      explanation.guidance = "the generation counter is exhausted; the object cannot be mutated";
      break;
    case OutcomeCode::REVOKED:
    case OutcomeCode::RETIRED:
    case OutcomeCode::WITHDRAWN:
    case OutcomeCode::SUPERSEDED:
      explanation.guidance = "the set is in a terminal governance state and accepts no mutation";
      break;
    default:
      explanation.guidance = "see the deterministic detail for the exact rejection cause";
      break;
  }
  return explanation;
}

std::string_view to_string(ExplanationReason reason) noexcept {
  switch (reason) {
    case ExplanationReason::SET_PUBLISHED_AND_THRESHOLD_MET:
      return "SET_PUBLISHED_AND_THRESHOLD_MET";
    case ExplanationReason::SET_BELOW_MINIMUM: return "SET_BELOW_MINIMUM";
    case ExplanationReason::SET_ZERO_USABLE_MEMBERS: return "SET_ZERO_USABLE_MEMBERS";
    case ExplanationReason::SET_ADMIN_DISABLED: return "SET_ADMIN_DISABLED";
    case ExplanationReason::SET_CURRENTNESS_NOT_ESTABLISHED:
      return "SET_CURRENTNESS_NOT_ESTABLISHED";
    case ExplanationReason::SET_NOT_PUBLISHED: return "SET_NOT_PUBLISHED";
    case ExplanationReason::SET_WITHDRAWN: return "SET_WITHDRAWN";
    case ExplanationReason::SET_SUPERSEDED: return "SET_SUPERSEDED";
    case ExplanationReason::SET_REVOKED: return "SET_REVOKED";
    case ExplanationReason::SET_RETIRED: return "SET_RETIRED";
    case ExplanationReason::MEMBER_USABLE: return "MEMBER_USABLE";
    case ExplanationReason::MEMBER_PATH_AUTHORITY_GENERATION_STALE:
      return "MEMBER_PATH_AUTHORITY_GENERATION_STALE";
    case ExplanationReason::MEMBER_PATH_STATE_NOT_USABLE: return "MEMBER_PATH_STATE_NOT_USABLE";
    case ExplanationReason::MEMBER_PATH_CONDITIONALLY_NOT_PERMITTED:
      return "MEMBER_PATH_CONDITIONALLY_NOT_PERMITTED";
    case ExplanationReason::MEMBER_PATH_AUTHORITY_UNKNOWN: return "MEMBER_PATH_AUTHORITY_UNKNOWN";
    case ExplanationReason::MEMBER_ADMIN_DISABLED: return "MEMBER_ADMIN_DISABLED";
    case ExplanationReason::MEMBER_LIFECYCLE_NOT_CURRENT: return "MEMBER_LIFECYCLE_NOT_CURRENT";
    case ExplanationReason::MEMBER_SET_NOT_USABLE: return "MEMBER_SET_NOT_USABLE";
    case ExplanationReason::MEMBER_EPOCH_STALE: return "MEMBER_EPOCH_STALE";
    case ExplanationReason::MEMBER_AUTHORITY_FENCED: return "MEMBER_AUTHORITY_FENCED";
    case ExplanationReason::MEMBER_PENDING_EVALUATION: return "MEMBER_PENDING_EVALUATION";
    case ExplanationReason::MEMBER_PENDING_REVALIDATION: return "MEMBER_PENDING_REVALIDATION";
    case ExplanationReason::MINIMUM_MEMBERSHIP_UNSATISFIED:
      return "MINIMUM_MEMBERSHIP_UNSATISFIED";
    case ExplanationReason::EXPLANATION_TRUNCATED: return "EXPLANATION_TRUNCATED";
  }
  return "<invalid-explanation-reason>";
}

bool valid_explanation_reason(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 24; }

std::string MemberExplanation::render() const {
  std::ostringstream stream;
  stream << "member " << id.view() << " path=" << path_id.view()
         << " lifecycle=" << to_string(lifecycle) << " currentness=" << to_string(currentness)
         << " usable=" << (usable ? "true" : "false")
         << " admin_enabled=" << (admin_enabled ? "true" : "false")
         << " bound_authority_generation=" << bound_authority_generation.value();
  if (observed_authority_generation.has_value()) {
    stream << " observed_authority_generation=" << observed_authority_generation->value();
  }
  if (observed_authority_state.has_value()) {
    stream << " observed_authority_state=" << to_string(*observed_authority_state);
  }
  stream << " reason=" << to_string(reason);
  if (pending_revalidations > 0) {
    stream << " pending_revalidations=" << pending_revalidations;
  }
  return stream.str();
}

std::string SetExplanation::render() const {
  std::ostringstream stream;
  stream << "set " << set_id.view() << " key=" << key.render()
         << "\n  lifecycle=" << to_string(lifecycle) << " currentness=" << to_string(currentness)
         << " readiness=" << to_string(readiness)
         << "\n  members=" << member_count << " usable=" << usable_member_count
         << " minimum=" << minimum_usable_members
         << " minimum_satisfied=" << (minimum_satisfied ? "true" : "false")
         << " admin_enabled=" << (admin_enabled ? "true" : "false")
         << "\n  governing_epoch=" << governing_epoch.value()
         << " authority_generation=" << authority_generation.value()
         << " last_cause=" << to_string(last_cause);
  if (last_mutating_publisher.has_value()) {
    stream << " last_mutating_publisher=" << last_mutating_publisher->view();
  }
  stream << "\n  reasons:";
  for (const auto& reason : reasons) {
    stream << ' ' << to_string(reason);
  }
  for (const auto& member : members) {
    stream << "\n  " << member.render();
  }
  return stream.str();
}

std::string RejectionExplanation::render() const {
  std::ostringstream stream;
  stream << to_string(code) << " stage=" << to_string(stage)
         << " precedence=" << static_cast<unsigned>(precedence);
  if (!detail.empty()) {
    stream << "\n  detail: " << detail;
  }
  if (!guidance.empty()) {
    stream << "\n  guidance: " << guidance;
  }
  return stream.str();
}

}  // namespace multipath_fabric
