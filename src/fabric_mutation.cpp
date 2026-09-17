#include "engine_impl.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {
namespace {

[[nodiscard]] std::string delta_detail(const std::string& prefix, SetLifecycle before,
                                       SetLifecycle after) {
  std::ostringstream stream;
  stream << prefix << "; lifecycle " << to_string(before) << " -> " << to_string(after);
  return stream.str();
}

// Pre-flight check for a set generation advance. Callers run this before they
// mutate anything so that an exhausted counter never leaves a half-applied
// change behind.
[[nodiscard]] bool set_generation_available(const detail::SetRecord& record) noexcept {
  return record.generation.next().has_value();
}

[[nodiscard]] bool membership_generation_available(const detail::SetRecord& record) noexcept {
  return record.membership_generation.next().has_value();
}

[[nodiscard]] bool expected_set_generation_matches(const MutationContext& context,
                                                   const detail::SetRecord& record) {
  return !context.expected_set_generation.has_value() ||
         record.generation == *context.expected_set_generation;
}

[[nodiscard]] FabricOutcome stale_set_generation(const MutationContext& context,
                                                 const detail::SetRecord& record) {
  return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                        "expected set generation " +
                            std::to_string(context.expected_set_generation->value()) +
                            " but the set is at " + std::to_string(record.generation.value()));
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction and configuration
// ---------------------------------------------------------------------------

FabricEngine::FabricEngine(FabricConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}

FabricEngine::~FabricEngine() = default;

void FabricEngine::bind_path_authority(std::shared_ptr<const PathAuthoritySource> source) {
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  impl_->path_authority = source ? std::move(source) : impl_->directory;
}

FabricOutcome FabricEngine::declare_path_authority(const MutationContext& context,
                                                    const PathAuthorityView& view) {
  if (!view.path.valid() || !view.generation.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "declare_path_authority requires a valid path and generation");
  }
  const std::vector<std::string> fields{"declare_path_authority", view.path.str(),
                                        std::to_string(view.generation.value()),
                                        std::string(to_string(view.state))};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  if (!context.has_caller_identity()) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_CALLER,
                          "mutation context is missing a required caller identity element: " +
                              context.render());
  }
  if (!(context.epoch == impl_->current_epoch)) {
    return make_rejection(OutcomeCode::STALE_EPOCH,
                          "request epoch is not the governing epoch");
  }
  const auto fence_key = std::make_pair(context.publisher, context.worker_boot);
  if (impl_->fences.find(fence_key) != impl_->fences.end()) {
    return make_rejection(OutcomeCode::STALE_WORKER, "worker boot is fenced");
  }
  const auto registration = impl_->registrations.find(fence_key);
  if (registration == impl_->registrations.end() ||
      !(registration->second.epoch == impl_->current_epoch)) {
    return make_rejection(OutcomeCode::UNKNOWN_PUBLISHER,
                          "publisher/boot is not registered at the governing epoch");
  }
  if (const auto replay = impl_->attempt_check_locked(context, "declare_path_authority", fields);
      replay.has_value()) {
    return *replay;
  }
  if (impl_->path_authority != impl_->directory) {
    return make_rejection(OutcomeCode::UNSUPPORTED_OPERATION,
                          "an external Path Authority source is installed; the coordinator does "
                          "not own the Path Authority view for this path");
  }
  // Scope must cover every dependent set before the view is recorded.
  const auto dependents = impl_->path_dependents.find(view.path);
  if (dependents != impl_->path_dependents.end()) {
    for (const auto& set_id : dependents->second) {
      const auto set = impl_->sets.find(set_id);
      if (set == impl_->sets.end()) {
        continue;
      }
      if (!registration->second.scope.covers(set->second.key.fabric, set->second.key.name_space,
                                             set->second.id)) {
        return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE,
                              "scope does not cover dependent set " + set->second.key.render());
      }
    }
  }
  impl_->directory->set(view);
  const std::size_t changed = impl_->apply_view_locked(
      view.path, std::optional<PathAuthorityView>(view), &context,
      MembershipCause::PATH_INVALIDATED);
  std::ostringstream detail;
  detail << "declared Path Authority view for " << view.path.view() << " generation "
         << view.generation.value() << " state " << to_string(view.state) << "; " << changed
         << " dependent set(s) changed";
  FabricOutcome outcome = make_outcome(changed > 0 ? OutcomeCode::PATH_INVALIDATED
                                                   : OutcomeCode::UPDATED,
                                       detail.str());
  outcome.path_id = view.path;
  impl_->record_attempt_locked(context, "declare_path_authority", fields, outcome);
  return outcome;
}

bool FabricEngine::has_path_authority() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return static_cast<bool>(impl_->path_authority);
}

CoordinatorEpoch FabricEngine::epoch() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->current_epoch;
}

MultipathAuthorityGeneration FabricEngine::authority_generation() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->current_authority_generation;
}

Limits FabricEngine::limits() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->config.limits;
}

// ---------------------------------------------------------------------------
// create_set
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::create_set(const MutationContext& context, const SetKey& key,
                                       const SetOptions& options) {
  if (!key.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "set key requires a valid fabric, namespace and set name; received " +
                              key.render());
  }
  const std::vector<std::string> fields{
      "create_set", key.render(), std::to_string(options.minimum_usable_members),
      options.admin_enabled ? "1" : "0", options.conditional_authority_permitted ? "1" : "0"};

  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, key, std::nullopt);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "create_set", fields);
      replay.has_value()) {
    return *replay;
  }
  if (impl_->key_index.find(key) != impl_->key_index.end()) {
    return make_rejection(OutcomeCode::SET_KEY_CONFLICT,
                          "a set already exists for key " + key.render());
  }
  if (impl_->sets.size() >= impl_->config.limits.max_sets) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "max_sets limit reached: " +
                              std::to_string(impl_->config.limits.max_sets));
  }
  if (options.minimum_usable_members > impl_->config.limits.max_members_per_set) {
    return make_rejection(OutcomeCode::INVALID_THRESHOLD,
                          "minimum usable members " +
                              std::to_string(options.minimum_usable_members) +
                              " exceeds max_members_per_set " +
                              std::to_string(impl_->config.limits.max_members_per_set));
  }

  detail::SetRecord record;
  record.id = impl_->ids.next_set_id();
  record.key = key;
  record.generation = MultipathSetGeneration::first();
  record.membership_generation = MembershipGeneration::first();
  record.authority_generation = impl_->current_authority_generation;
  record.lifecycle = SetLifecycle::DECLARED;
  record.currentness = SetCurrentness::CURRENT;
  record.admin_enabled = options.admin_enabled;
  record.minimum_usable_members = options.minimum_usable_members;
  record.conditional_authority_permitted = options.conditional_authority_permitted;
  record.governing_epoch = impl_->current_epoch;
  record.usable_member_count = 0;
  record.provenance = impl_->make_provenance_locked(context, MembershipCause::DECLARED, record);

  const MultipathSetId created_id = record.id;
  impl_->sets.emplace(created_id, std::move(record));
  impl_->key_index.emplace(key, created_id);

  detail::SetRecord& stored = impl_->sets.at(created_id);
  impl_->append_history_locked(stored, SetEvent::DECLARE, MembershipCause::DECLARED, &context,
                               std::nullopt, std::nullopt,
                               "declared set " + key.render() + " minimum=" +
                                   std::to_string(options.minimum_usable_members));
  impl_->capture_snapshot_locked(stored);

  FabricOutcome outcome = make_outcome(OutcomeCode::CREATED, "created set " + key.render());
  impl_->finalize_outcome_locked(stored, outcome);
  impl_->record_attempt_locked(context, "create_set", fields, outcome);
  return outcome;
}

// ---------------------------------------------------------------------------
// Set lifecycle operations
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::publish_set(const MutationContext& context,
                                        const MultipathSetId& set_id) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "publish_set requires a set identity");
  }
  const std::vector<std::string> fields{"publish_set", set_id.str()};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "publish_set", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  const SetLifecycle before = record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::PUBLISH);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  CommitSpec spec;
  spec.event = SetEvent::PUBLISH;
  spec.cause = MembershipCause::SET_PUBLISHED;
  spec.summary = delta_detail("published set", before, record->lifecycle);
  return impl_->commit_locked(*record, context, "publish_set", fields, spec,
                              make_outcome(OutcomeCode::SET_PUBLISHED, spec.summary));
}

FabricOutcome FabricEngine::set_minimum_usable_members(const MutationContext& context,
                                                       const MultipathSetId& set_id,
                                                       std::uint64_t minimum_usable_members) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "set_minimum_usable_members requires a set identity");
  }
  const std::vector<std::string> fields{"set_minimum_usable_members", set_id.str(),
                                        std::to_string(minimum_usable_members)};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay =
          impl_->attempt_check_locked(context, "set_minimum_usable_members", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::MINIMUM_CHANGED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  if (minimum_usable_members > impl_->config.limits.max_members_per_set) {
    return make_rejection(OutcomeCode::INVALID_THRESHOLD,
                          "minimum usable members " + std::to_string(minimum_usable_members) +
                              " exceeds max_members_per_set " +
                              std::to_string(impl_->config.limits.max_members_per_set));
  }
  if (record->minimum_usable_members == minimum_usable_members) {
    FabricOutcome outcome = make_outcome(
        OutcomeCode::IDEMPOTENT,
        "minimum usable members already " + std::to_string(minimum_usable_members));
    impl_->finalize_outcome_locked(*record, outcome);
    impl_->record_attempt_locked(context, "set_minimum_usable_members", fields, outcome);
    return outcome;
  }
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  const std::uint64_t before = record->minimum_usable_members;
  record->minimum_usable_members = minimum_usable_members;
  impl_->recompute_locked(*record);
  CommitSpec spec;
  spec.event = SetEvent::MINIMUM_CHANGED;
  spec.cause = MembershipCause::MINIMUM_CHANGED;
  spec.summary = "minimum usable members " + std::to_string(before) + " -> " +
                 std::to_string(minimum_usable_members) + " lifecycle=" +
                 std::string(to_string(record->lifecycle));
  return impl_->commit_locked(*record, context, "set_minimum_usable_members", fields, spec,
                              make_outcome(OutcomeCode::UPDATED, spec.summary));
}

FabricOutcome FabricEngine::set_conditional_authority_policy(const MutationContext& context,
                                                             const MultipathSetId& set_id,
                                                             bool permitted) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "set_conditional_authority_policy requires a set identity");
  }
  const std::vector<std::string> fields{"set_conditional_authority_policy", set_id.str(),
                                        permitted ? "1" : "0"};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay =
          impl_->attempt_check_locked(context, "set_conditional_authority_policy", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::POLICY_CHANGED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  if (record->conditional_authority_permitted == permitted) {
    FabricOutcome outcome =
        make_outcome(OutcomeCode::IDEMPOTENT,
                     std::string("conditional Path Authority policy already ") +
                         (permitted ? "permitted" : "denied"));
    impl_->finalize_outcome_locked(*record, outcome);
    impl_->record_attempt_locked(context, "set_conditional_authority_policy", fields, outcome);
    return outcome;
  }
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  record->conditional_authority_permitted = permitted;
  // The declared policy participates in member classification, so withdrawing or
  // granting conditional authorization immediately re-derives every member that
  // was evaluated against the previous policy.
  impl_->reevaluate_members_from_observations_locked(*record);
  CommitSpec spec;
  spec.event = SetEvent::POLICY_CHANGED;
  spec.cause = MembershipCause::POLICY_CHANGED;
  spec.summary = std::string("conditional Path Authority policy -> ") +
                 (permitted ? "permitted" : "denied");
  return impl_->commit_locked(*record, context, "set_conditional_authority_policy", fields, spec,
                              make_outcome(OutcomeCode::UPDATED, spec.summary));
}

FabricOutcome FabricEngine::set_admin_enabled(const MutationContext& context,
                                              const MultipathSetId& set_id, bool enabled) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "set_admin_enabled requires a set identity");
  }
  const std::vector<std::string> fields{"set_admin_enabled", set_id.str(), enabled ? "1" : "0"};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "set_admin_enabled", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  if (const auto rejection = impl_->apply_transition_locked(
          *record, enabled ? SetEvent::ADMIN_ENABLED : SetEvent::ADMIN_DISABLED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  if (record->admin_enabled == enabled) {
    FabricOutcome outcome = make_outcome(
        OutcomeCode::IDEMPOTENT,
        std::string("administrative enablement already ") + (enabled ? "true" : "false"));
    impl_->finalize_outcome_locked(*record, outcome);
    impl_->record_attempt_locked(context, "set_admin_enabled", fields, outcome);
    return outcome;
  }
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  record->admin_enabled = enabled;
  impl_->recompute_locked(*record);
  CommitSpec spec;
  spec.event = enabled ? SetEvent::ADMIN_ENABLED : SetEvent::ADMIN_DISABLED;
  spec.cause = enabled ? MembershipCause::ADMIN_ENABLED : MembershipCause::ADMIN_DISABLED;
  spec.summary = std::string("administrative enablement -> ") + (enabled ? "true" : "false") +
                 " lifecycle=" + std::string(to_string(record->lifecycle));
  return impl_->commit_locked(*record, context, "set_admin_enabled", fields, spec,
                              make_outcome(OutcomeCode::UPDATED, spec.summary));
}

FabricOutcome FabricEngine::withdraw_set(const MutationContext& context,
                                         const MultipathSetId& set_id, std::string reason) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "withdraw_set requires a set identity");
  }
  if (reason.size() > 256) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "withdrawal reason exceeds the 256 character bound");
  }
  const std::vector<std::string> fields{"withdraw_set", set_id.str(), reason};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "withdraw_set", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  const SetLifecycle before = record->lifecycle;
  if (before == SetLifecycle::WITHDRAWING) {
    if (record->withdrawal_reason == reason) {
      FabricOutcome outcome =
          make_outcome(OutcomeCode::IDEMPOTENT, "set is already withdrawing for the same reason");
      impl_->finalize_outcome_locked(*record, outcome);
      impl_->record_attempt_locked(context, "withdraw_set", fields, outcome);
      return outcome;
    }
    return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                          "set is already withdrawing for a different reason");
  }
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::BEGIN_WITHDRAW);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  record->withdrawal_reason = reason;
  impl_->recompute_locked(*record);
  impl_->apply_member_consequences_locked(*record, before, record->lifecycle, &context);
  CommitSpec spec;
  spec.event = SetEvent::BEGIN_WITHDRAW;
  spec.cause = MembershipCause::SET_WITHDRAWN;
  spec.summary = "withdrawal begun: " + reason;
  return impl_->commit_locked(*record, context, "withdraw_set", fields, spec,
                              make_outcome(OutcomeCode::SET_WITHDRAWING, spec.summary));
}

FabricOutcome FabricEngine::complete_withdrawal(const MutationContext& context,
                                                const MultipathSetId& set_id) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "complete_withdrawal requires a set identity");
  }
  const std::vector<std::string> fields{"complete_withdrawal", set_id.str()};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "complete_withdrawal", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  const SetLifecycle before = record->lifecycle;
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::COMPLETE_WITHDRAW);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  CommitSpec spec;
  spec.event = SetEvent::COMPLETE_WITHDRAW;
  spec.cause = MembershipCause::SET_WITHDRAWN;
  spec.summary = "withdrawal completed";
  return impl_->commit_locked(*record, context, "complete_withdrawal", fields, spec,
                              make_outcome(OutcomeCode::SET_WITHDRAWN, spec.summary));
}

FabricOutcome FabricEngine::revoke_set(const MutationContext& context,
                                       const MultipathSetId& set_id, RevocationReason reason,
                                       std::string detail) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "revoke_set requires a set identity");
  }
  if (detail.size() > 512) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "revocation detail exceeds the 512 character bound");
  }
  const std::vector<std::string> fields{"revoke_set", set_id.str(), std::string(to_string(reason)),
                                        detail};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "revoke_set", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  if (record->lifecycle == SetLifecycle::REVOKED && record->revocation.has_value()) {
    if (record->revocation->reason == reason && record->revocation->detail == detail) {
      FabricOutcome outcome = make_outcome(
          OutcomeCode::IDEMPOTENT, "set is already revoked with the same reason code");
      impl_->finalize_outcome_locked(*record, outcome);
      impl_->record_attempt_locked(context, "revoke_set", fields, outcome);
      return outcome;
    }
    return make_rejection(OutcomeCode::REVOKED,
                          "set is already revoked with a different reason code: " +
                              record->revocation->render());
  }
  const auto next_generation = record->generation.next();
  if (!next_generation.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  const SetLifecycle before = record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::REVOKE);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  RevocationRecord revocation;
  revocation.set_id = set_id;
  // Generation-bound: the revocation records the generation produced by the
  // commit that made it durable.
  revocation.generation = *next_generation;
  revocation.authority_generation = impl_->current_authority_generation;
  revocation.epoch = context.epoch;
  revocation.publisher = context.publisher;
  revocation.reason = reason;
  revocation.detail = detail;
  record->revocation = revocation;
  impl_->apply_member_consequences_locked(*record, before, record->lifecycle, &context);
  CommitSpec spec;
  spec.event = SetEvent::REVOKE;
  spec.cause = MembershipCause::SET_REVOKED;
  spec.summary = "revoked: " + std::string(to_string(reason)) +
                 (detail.empty() ? std::string() : " (" + detail + ")");
  return impl_->commit_locked(*record, context, "revoke_set", fields, spec,
                              make_outcome(OutcomeCode::SET_REVOKED, spec.summary));
}

FabricOutcome FabricEngine::retire_set(const MutationContext& context,
                                       const MultipathSetId& set_id, std::string reason) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "retire_set requires a set identity");
  }
  if (reason.size() > 256) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "retirement reason exceeds the 256 character bound");
  }
  const std::vector<std::string> fields{"retire_set", set_id.str(), reason};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "retire_set", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!expected_set_generation_matches(context, *record)) {
    return stale_set_generation(context, *record);
  }
  const SetLifecycle before = record->lifecycle;
  if (!set_generation_available(*record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + set_id.str());
  }
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::RETIRE);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  impl_->apply_member_consequences_locked(*record, before, record->lifecycle, &context);
  CommitSpec spec;
  spec.event = SetEvent::RETIRE;
  spec.cause = MembershipCause::SET_RETIRED;
  spec.summary = "retired: " + reason;
  return impl_->commit_locked(*record, context, "retire_set", fields, spec,
                              make_outcome(OutcomeCode::SET_RETIRED, spec.summary));
}

FabricOutcome FabricEngine::supersede_set(const MutationContext& context,
                                          const MultipathSetId& predecessor,
                                          const MultipathSetId& successor) {
  if (!predecessor.valid() || !successor.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "supersede_set requires two valid set identities");
  }
  if (predecessor == successor) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "a set cannot supersede itself: " + predecessor.str());
  }
  const std::vector<std::string> fields{"supersede_set", predecessor.str(), successor.str()};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority =
      impl_->authority_check_locked(context, std::nullopt, predecessor);
  if (!authority.succeeded()) {
    return authority;
  }
  const FabricOutcome successor_authority =
      impl_->authority_check_locked(context, std::nullopt, successor);
  if (!successor_authority.succeeded()) {
    return successor_authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "supersede_set", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* old_record = nullptr;
  const FabricOutcome located_old = impl_->require_set_locked(predecessor, old_record);
  if (!located_old.succeeded()) {
    return located_old;
  }
  detail::SetRecord* new_record = nullptr;
  const FabricOutcome located_new = impl_->require_set_locked(successor, new_record);
  if (!located_new.succeeded()) {
    return located_new;
  }
  if (!expected_set_generation_matches(context, *old_record)) {
    return stale_set_generation(context, *old_record);
  }
  if (old_record->superseded_by.has_value() && *old_record->superseded_by == successor) {
    FabricOutcome outcome = make_outcome(
        OutcomeCode::IDEMPOTENT, "set is already superseded by the same successor");
    impl_->finalize_outcome_locked(*old_record, outcome);
    impl_->record_attempt_locked(context, "supersede_set", fields, outcome);
    return outcome;
  }
  if (!set_generation_available(*old_record)) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath set generation is exhausted for " + predecessor.str());
  }
  const SetLifecycle before = old_record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*old_record, SetEvent::SUPERSEDE);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, predecessor);
  }
  // Supersession never leaves two simultaneous authorities: the predecessor
  // stops being authoritative in the same commit that records its successor.
  old_record->superseded_by = successor;
  new_record->supersedes = predecessor;
  impl_->apply_member_consequences_locked(*old_record, before, old_record->lifecycle, &context);

  CommitSpec spec;
  spec.event = SetEvent::SUPERSEDE;
  spec.cause = MembershipCause::SET_SUPERSEDED;
  spec.summary = "superseded by " + successor.str();
  FabricOutcome outcome = make_outcome(OutcomeCode::SET_SUPERSEDED, spec.summary);
  const FabricOutcome committed =
      impl_->commit_locked(*old_record, context, "supersede_set", fields, spec, outcome);
  if (!committed.succeeded()) {
    return committed;
  }
  impl_->append_history_locked(*new_record, SetEvent::SUPERSEDE,
                               MembershipCause::SET_SUPERSEDED, &context, std::nullopt,
                               std::nullopt, "supersedes " + predecessor.str());
  impl_->capture_snapshot_locked(*new_record);
  return committed;
}

}  // namespace multipath_fabric
