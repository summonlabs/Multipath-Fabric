#include "engine_impl.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {

// ---------------------------------------------------------------------------
// Publisher registration
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::register_publisher(const PublisherId& publisher,
                                               const WorkerBootId& worker_boot,
                                               const AuthorityScope& scope,
                                               const SessionId& session) {
  if (!publisher.valid() || !worker_boot.valid() || !session.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "register_publisher requires a publisher, a worker boot and a session "
                          "identity");
  }
  if (!scope.well_formed()) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE,
                          "authority scope must name a fabric and a multipath namespace; "
                          "default deny");
  }
  if (scope.set_ids.size() > impl_->config.limits.max_scope_set_ids) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "scope lists " + std::to_string(scope.set_ids.size()) +
                              " set ids which exceeds max_scope_set_ids " +
                              std::to_string(impl_->config.limits.max_scope_set_ids));
  }
  for (const auto& set_id : scope.set_ids) {
    if (!set_id.valid()) {
      return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                            "authority scope contains an invalid set identity");
    }
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto key = std::make_pair(publisher, worker_boot);
  if (impl_->fences.find(key) != impl_->fences.end()) {
    return make_rejection(OutcomeCode::STALE_WORKER,
                          "worker boot is permanently fenced: " + impl_->fences.at(key).render());
  }
  const auto existing = impl_->registrations.find(key);
  if (existing != impl_->registrations.end()) {
    const PublisherRegistration& current = existing->second;
    if (current.epoch == impl_->current_epoch && current.session == session &&
        current.scope.fabric == scope.fabric && current.scope.name_space == scope.name_space &&
        current.scope.set_ids == scope.set_ids) {
      FabricOutcome outcome = make_outcome(
          OutcomeCode::IDEMPOTENT,
          "publisher/boot is already registered with the same scope: " + current.render());
      return outcome;
    }
  } else if (impl_->registrations.size() >= impl_->config.limits.max_publishers) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "max_publishers limit of " +
                              std::to_string(impl_->config.limits.max_publishers) + " reached");
  }

  // One session holds at most one publisher/boot registration.
  for (auto it = impl_->registrations.begin(); it != impl_->registrations.end();) {
    if (it->second.session == session && it->first != key) {
      it = impl_->registrations.erase(it);
    } else {
      ++it;
    }
  }

  const auto next_authority = impl_->current_authority_generation.next();
  if (!next_authority.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath authority generation is exhausted");
  }
  impl_->current_authority_generation = *next_authority;

  PublisherRegistration registration;
  registration.publisher = publisher;
  registration.worker_boot = worker_boot;
  registration.scope = scope;
  registration.epoch = impl_->current_epoch;
  registration.authority_generation = impl_->current_authority_generation;
  registration.session = session;
  impl_->registrations[key] = registration;

  FabricOutcome outcome = make_outcome(OutcomeCode::PUBLISHER_REGISTERED,
                                       "registered " + registration.render());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

FabricOutcome FabricEngine::unregister_publisher(const PublisherId& publisher,
                                                 const WorkerBootId& worker_boot) {
  if (!publisher.valid() || !worker_boot.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "unregister_publisher requires a publisher and a worker boot identity");
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto key = std::make_pair(publisher, worker_boot);
  const auto existing = impl_->registrations.find(key);
  if (existing == impl_->registrations.end()) {
    return make_rejection(OutcomeCode::UNKNOWN_PUBLISHER,
                          "publisher/boot is not registered: " + publisher.str() + "/" +
                              worker_boot.str());
  }
  impl_->registrations.erase(existing);
  const auto next_authority = impl_->current_authority_generation.next();
  if (next_authority.has_value()) {
    impl_->current_authority_generation = *next_authority;
  }
  FabricOutcome outcome = make_outcome(OutcomeCode::PUBLISHER_UNREGISTERED,
                                       "unregistered " + publisher.str() + "/" +
                                           worker_boot.str());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

FabricOutcome FabricEngine::fence_worker(const PublisherId& publisher,
                                         const WorkerBootId& worker_boot, std::string cause) {
  if (!publisher.valid() || !worker_boot.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "fence_worker requires a publisher and a worker boot identity");
  }
  if (cause.empty() || cause.size() > 64) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "fence cause must be a non-empty string of at most 64 characters");
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto key = std::make_pair(publisher, worker_boot);
  if (impl_->fences.find(key) != impl_->fences.end()) {
    FabricOutcome outcome = make_outcome(OutcomeCode::IDEMPOTENT,
                                         "worker boot is already fenced: " +
                                             impl_->fences.at(key).render());
    return outcome;
  }
  const auto next_authority = impl_->current_authority_generation.next();
  if (!next_authority.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath authority generation is exhausted");
  }
  FenceRecord fence;
  fence.publisher = publisher;
  fence.worker_boot = worker_boot;
  fence.epoch = impl_->current_epoch;
  fence.cause = cause;
  impl_->fences[key] = fence;
  impl_->registrations.erase(key);
  // Permanent fencing: the pair stays in the fence table for the life of the
  // store and rejects every future request regardless of epoch.
  impl_->current_authority_generation = *next_authority;

  // Live currentness of a set was established under the authority that last
  // mutated it. When that authority is fenced, the durable membership
  // description survives but live currentness must be re-established.
  std::size_t affected = 0;
  for (auto& entry : impl_->sets) {
    detail::SetRecord& record = entry.second;
    if (!(record.provenance.publisher == publisher)) {
      continue;
    }
    if (record.currentness != SetCurrentness::REVALIDATION_REQUIRED) {
      record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
      ++affected;
    }
    record.authority_generation = impl_->current_authority_generation;
    record.governing_epoch = impl_->current_epoch;
    impl_->bump_set_watermark_locked(record);
    impl_->capture_snapshot_locked(record);
  }
  std::ostringstream detail;
  detail << "fenced " << publisher.view() << '/' << worker_boot.view() << " cause=" << cause
         << "; " << affected << " set(s) moved to currentness REVALIDATION_REQUIRED";
  FabricOutcome outcome = make_outcome(OutcomeCode::WORKER_FENCED, detail.str());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

FabricOutcome FabricEngine::advance_epoch(const PublisherId& publisher,
                                          const WorkerBootId& worker_boot,
                                          const SessionId& session,
                                          const CoordinatorEpoch& expected_epoch,
                                          const MutationAttemptId& attempt) {
  if (!publisher.valid() || !worker_boot.valid() || !session.valid() || !attempt.valid() ||
      !expected_epoch.valid()) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_CALLER,
                          "advance_epoch requires a publisher, worker boot, session, expected "
                          "epoch and attempt identity");
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto key = std::make_pair(publisher, worker_boot);
  if (impl_->fences.find(key) != impl_->fences.end()) {
    return make_rejection(OutcomeCode::STALE_WORKER,
                          "worker boot is fenced: " + impl_->fences.at(key).render());
  }
  const auto registration = impl_->registrations.find(key);
  if (registration == impl_->registrations.end()) {
    return make_rejection(OutcomeCode::UNKNOWN_PUBLISHER,
                          "publisher/boot is not registered at the governing epoch");
  }
  if (!(registration->second.session == session)) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_CALLER,
                          "session does not own the registration for " + publisher.str() + "/" +
                              worker_boot.str());
  }
  if (!(expected_epoch == impl_->current_epoch)) {
    return make_rejection(OutcomeCode::STALE_EPOCH,
                          "expected epoch " + std::to_string(expected_epoch.value()) +
                              " is not the governing epoch " +
                              std::to_string(impl_->current_epoch.value()));
  }
  // Epoch advancement is not replay-recognized: a repeat of the same request
  // necessarily carries the superseded epoch and is rejected at the EPOCH stage,
  // which precedes attempt classification in the fixed precedence.
  const auto next_epoch = impl_->current_epoch.next();
  if (!next_epoch.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "coordinator epoch is exhausted");
  }
  const auto next_authority = impl_->current_authority_generation.next();
  if (!next_authority.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "multipath authority generation is exhausted");
  }
  // Every existing registration belongs to the old epoch. They are dropped and
  // permanently fenced so that no previous worker boot can mutate again.
  for (const auto& entry : impl_->registrations) {
    FenceRecord fence;
    fence.publisher = entry.first.first;
    fence.worker_boot = entry.first.second;
    fence.epoch = *next_epoch;
    fence.cause = "EPOCH_ADVANCE";
    impl_->fences[entry.first] = fence;
  }
  impl_->registrations.clear();
  impl_->current_epoch = *next_epoch;
  impl_->current_authority_generation = *next_authority;

  // Durable membership descriptions survive. Live currentness does not.
  for (auto& entry : impl_->sets) {
    detail::SetRecord& record = entry.second;
    record.authority_generation = impl_->current_authority_generation;
    record.governing_epoch = impl_->current_epoch;
    record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
    impl_->bump_set_watermark_locked(record);
    impl_->append_history_locked(record, SetEvent::EPOCH_ADVANCE,
                                 MembershipCause::EPOCH_ADVANCE, nullptr, std::nullopt,
                                 std::nullopt,
                                 "epoch advanced to " +
                                     std::to_string(impl_->current_epoch.value()));
    impl_->capture_snapshot_locked(record);
  }
  std::ostringstream detail;
  detail << "epoch advanced to " << impl_->current_epoch.value() << "; authority generation "
         << impl_->current_authority_generation.value() << "; all registrations fenced and "
         << impl_->sets.size() << " set(s) moved to currentness REVALIDATION_REQUIRED";
  FabricOutcome outcome = make_outcome(OutcomeCode::EPOCH_ADVANCED, detail.str());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

bool FabricEngine::is_fenced(const PublisherId& publisher, const WorkerBootId& worker_boot) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->fences.find(std::make_pair(publisher, worker_boot)) != impl_->fences.end();
}

std::optional<PublisherRegistration> FabricEngine::find_registration(
    const PublisherId& publisher, const WorkerBootId& worker_boot) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->registrations.find(std::make_pair(publisher, worker_boot));
  if (found == impl_->registrations.end()) {
    return std::nullopt;
  }
  return found->second;
}

AuthorityDescription FabricEngine::describe_authority() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  AuthorityDescription description;
  description.epoch = impl_->current_epoch;
  description.authority_generation = impl_->current_authority_generation;
  for (const auto& entry : impl_->registrations) {
    description.registrations.push_back(entry.second);
  }
  for (const auto& entry : impl_->fences) {
    description.fence_records.push_back(entry.second);
  }
  return description;
}

}  // namespace multipath_fabric
