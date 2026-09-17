#include "engine_impl.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

bool member_inputs_usable(const detail::MemberRecord& member) noexcept {
  return member_is_usable(member.lifecycle, member.currentness) && member.admin_enabled;
}

bool set_is_consumable(const detail::SetRecord& record) noexcept {
  if (!record.published() || !record.admin_enabled) {
    return false;
  }
  if (record.currentness != SetCurrentness::CURRENT) {
    return false;
  }
  return record.lifecycle == SetLifecycle::ACTIVE || record.lifecycle == SetLifecycle::DEGRADED;
}

std::uint64_t consumable_member_count(const detail::SetRecord& record) noexcept {
  return set_is_consumable(record) ? record.usable_member_count : 0;
}

bool currentness_is_revalidation_recoverable(MemberCurrentness value) noexcept {
  switch (value) {
    case MemberCurrentness::STALE_PATH_AUTHORITY:
    case MemberCurrentness::PATH_REVALIDATION_REQUIRED:
    case MemberCurrentness::PATH_STALE:
    case MemberCurrentness::PATH_AUTHORITY_UNKNOWN:
    case MemberCurrentness::EPOCH_STALE:
    case MemberCurrentness::PENDING_EVALUATION:
      return true;
    case MemberCurrentness::CURRENT:
    case MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED:
    case MemberCurrentness::PATH_REJECTED:
    case MemberCurrentness::PATH_REVOKED:
    case MemberCurrentness::PATH_RETIRED:
    case MemberCurrentness::ADMIN_DISABLED:
    case MemberCurrentness::SET_NOT_USABLE:
    case MemberCurrentness::AUTHORITY_FENCED:
      return false;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Impl construction
// ---------------------------------------------------------------------------

FabricEngine::Impl::Impl(FabricConfig config_value)
    : config(std::move(config_value)),
      current_epoch(config.initial_epoch.valid() ? config.initial_epoch
                                                 : CoordinatorEpoch::first()),
      current_authority_generation(config.initial_authority_generation.valid()
                                       ? config.initial_authority_generation
                                       : MultipathAuthorityGeneration::first()),
      directory(std::make_shared<PathAuthorityDirectory>()),
      ids("mpf") {
  path_authority = directory;
}

// ---------------------------------------------------------------------------
// Authority checks (stages 2-6)
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::Impl::authority_check_locked(
    const MutationContext& context, const std::optional<SetKey>& key,
    const std::optional<MultipathSetId>& set_id) const {
  // Stage 2: caller identity.
  if (!context.epoch.valid() || !context.publisher.valid() || !context.worker_boot.valid() ||
      !context.session.valid() || !context.attempt.valid()) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_CALLER,
                          "mutation context is missing a required caller identity element: " +
                              context.render());
  }
  // Stage 3: governing epoch currency.
  if (!(context.epoch == current_epoch)) {
    std::ostringstream stream;
    stream << "request epoch " << context.epoch.value() << " is not the governing epoch "
           << current_epoch.value();
    return make_rejection(OutcomeCode::STALE_EPOCH, stream.str());
  }
  // Stage 4: worker boot authority and fencing.
  const auto fence_key = std::make_pair(context.publisher, context.worker_boot);
  const auto fence = fences.find(fence_key);
  if (fence != fences.end()) {
    return make_rejection(OutcomeCode::STALE_WORKER,
                          "worker boot is fenced: " + fence->second.render());
  }
  const auto registration = registrations.find(fence_key);
  if (registration == registrations.end()) {
    return make_rejection(OutcomeCode::UNKNOWN_PUBLISHER,
                          "publisher/boot is not registered at the governing epoch: " +
                              context.publisher.str() + "/" + context.worker_boot.str());
  }
  if (!(registration->second.epoch == current_epoch)) {
    std::ostringstream stream;
    stream << "registration for " << context.publisher.view() << '/'
           << context.worker_boot.view() << " belongs to epoch "
           << registration->second.epoch.value() << ", not the governing epoch "
           << current_epoch.value();
    return make_rejection(OutcomeCode::STALE_WORKER, stream.str());
  }
  // Stage 5: authority scope.
  const AuthorityScope& scope = registration->second.scope;
  if (key.has_value()) {
    // Creating a set: the requested key carries the fabric and namespace, and a
    // set-restricted scope can never authorize creating an unidentified set.
    if (!scope.covers_namespace(key->fabric, key->name_space)) {
      std::ostringstream stream;
      stream << "scope " << scope.render() << " does not cover namespace "
             << key->render();
      return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE, stream.str());
    }
    return make_outcome(OutcomeCode::OK, std::string());
  }
  if (!set_id.has_value()) {
    return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE,
                          "operation requires a set identity to evaluate authority scope");
  }
  const auto found = sets.find(*set_id);
  if (found == sets.end()) {
    // The set is unknown. A scope that explicitly lists set ids can still be
    // evaluated and is enforced at the SCOPE stage; a namespace-wide scope
    // cannot be evaluated, so the request falls through to SET_NOT_FOUND.
    if (!scope.covers_all_in_scope() &&
        std::find(scope.set_ids.begin(), scope.set_ids.end(), *set_id) == scope.set_ids.end()) {
      return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE,
                            "set " + set_id->str() + " is outside scope " + scope.render());
    }
    return make_rejection(OutcomeCode::SET_NOT_FOUND, "no such set: " + set_id->str());
  }
  const detail::SetRecord& record = found->second;
  if (!scope.covers(record.key.fabric, record.key.name_space, record.id)) {
    std::ostringstream stream;
    stream << "scope " << scope.render() << " does not cover set " << record.key.render();
    return make_rejection(OutcomeCode::UNAUTHORIZED_SCOPE, stream.str());
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

std::optional<FabricOutcome> FabricEngine::Impl::attempt_check_locked(
    const MutationContext& context, std::string_view operation,
    const std::vector<std::string>& fields) const {
  const auto known = attempt_index.find(context.attempt);
  if (known == attempt_index.end()) {
    return std::nullopt;
  }
  const detail::Digest128 fingerprint = detail::fingerprint_request(operation, fields);
  if (!(known->second == fingerprint)) {
    return make_rejection(OutcomeCode::ATTEMPT_CONFLICT,
                          "attempt " + context.attempt.str() +
                              " was already used for a different semantic request");
  }
  // Exact replay: return the recorded result without touching any state.
  for (const auto& record : attempts) {
    if (record.attempt == context.attempt) {
      FabricOutcome replay = record.outcome;
      replay.code = OutcomeCode::IDEMPOTENT;
      replay.stage = RejectionStage::NONE;
      replay.detail = "exact replay of an already-committed attempt; original outcome " +
                      std::string(to_string(record.outcome.code));
      return replay;
    }
  }
  return make_rejection(OutcomeCode::ATTEMPT_CONFLICT,
                        "attempt index and attempt log disagree for " + context.attempt.str());
}

void FabricEngine::Impl::record_attempt_locked(const MutationContext& context,
                                               std::string_view operation,
                                               const std::vector<std::string>& fields,
                                               const FabricOutcome& outcome) {
  AttemptRecord record;
  record.attempt = context.attempt;
  record.fingerprint = detail::fingerprint_request(operation, fields);
  record.outcome = outcome;
  attempts.push_back(std::move(record));
  attempt_index[context.attempt] = detail::fingerprint_request(operation, fields);
  trim_attempts_locked();
}

void FabricEngine::Impl::trim_attempts_locked() {
  while (attempts.size() > config.limits.max_attempts) {
    const AttemptRecord& front = attempts.front();
    const auto known = attempt_index.find(front.attempt);
    if (known != attempt_index.end() && known->second == front.fingerprint) {
      attempt_index.erase(known);
    }
    attempts.pop_front();
  }
}

// ---------------------------------------------------------------------------
// Lookup and lifecycle
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::Impl::require_set_locked(const MultipathSetId& set_id,
                                                     detail::SetRecord*& out) {
  const auto found = sets.find(set_id);
  if (found == sets.end()) {
    return make_rejection(OutcomeCode::SET_NOT_FOUND, "no such set: " + set_id.str());
  }
  out = &found->second;
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome FabricEngine::Impl::lifecycle_rejection(SetLifecycle lifecycle,
                                                      const MultipathSetId& set_id) {
  const std::string subject = "set " + set_id.str();
  switch (lifecycle) {
    case SetLifecycle::RETIRED:
      return make_rejection(OutcomeCode::RETIRED, subject + " is retired");
    case SetLifecycle::REVOKED:
      return make_rejection(OutcomeCode::REVOKED, subject + " is revoked");
    case SetLifecycle::WITHDRAWN:
      return make_rejection(OutcomeCode::WITHDRAWN, subject + " is withdrawn");
    case SetLifecycle::WITHDRAWING:
      return make_rejection(OutcomeCode::WITHDRAWN, subject + " is withdrawing");
    case SetLifecycle::SUPERSEDED:
      return make_rejection(OutcomeCode::SUPERSEDED, subject + " is superseded");
    default:
      return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                            subject + " does not accept this event in lifecycle " +
                                std::string(to_string(lifecycle)));
  }
}

FabricOutcome FabricEngine::Impl::currentness_rejection(MemberCurrentness currentness,
                                                        const PathId& path) {
  switch (currentness) {
    case MemberCurrentness::STALE_PATH_AUTHORITY:
      return make_rejection(OutcomeCode::STALE_PATH_AUTHORITY,
                            "path " + path.str() +
                                " is bound at a Path Authority generation that is no longer "
                                "current; explicit revalidation is required");
    case MemberCurrentness::PATH_AUTHORITY_UNKNOWN:
      return make_rejection(OutcomeCode::PATH_AUTHORITY_UNKNOWN,
                            "Path Authority has no record for path " + path.str());
    default:
      return make_rejection(OutcomeCode::PATH_NOT_USABLE,
                            "path " + path.str() + " is not usable: " +
                                std::string(to_string(currentness)));
  }
}

std::optional<OutcomeCode> FabricEngine::Impl::apply_transition_locked(
    detail::SetRecord& record, SetEvent event) {
  switch (set_transition(record.lifecycle, event)) {
    case SetTransitionAction::REJECT:
      return lifecycle_rejection(record.lifecycle, record.id).code;
    case SetTransitionAction::STAY:
      return std::nullopt;
    case SetTransitionAction::RECOMPUTE:
      recompute_locked(record);
      return std::nullopt;
    case SetTransitionAction::BECOME_PUBLISHED:
      // Publication enters the derived lifecycle directly: the set leaves
      // DECLARED, which recompute_locked() deliberately never overwrites.
      record.usable_member_count = record.recompute_usable_members();
      record.lifecycle = derive_published_lifecycle(record.usable_member_count,
                                                    record.minimum_usable_members,
                                                    record.admin_enabled);
      return std::nullopt;
    case SetTransitionAction::BECOME_ADMIN_DISABLED:
      record.lifecycle = SetLifecycle::ADMIN_DISABLED;
      return std::nullopt;
    case SetTransitionAction::BECOME_WITHDRAWING:
      record.lifecycle = SetLifecycle::WITHDRAWING;
      return std::nullopt;
    case SetTransitionAction::BECOME_WITHDRAWN:
      record.lifecycle = SetLifecycle::WITHDRAWN;
      // A terminal set has no live currentness to report.
      record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
      return std::nullopt;
    case SetTransitionAction::BECOME_SUPERSEDED:
      record.lifecycle = SetLifecycle::SUPERSEDED;
      record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
      return std::nullopt;
    case SetTransitionAction::BECOME_REVOKED:
      record.lifecycle = SetLifecycle::REVOKED;
      record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
      return std::nullopt;
    case SetTransitionAction::BECOME_RETIRED:
      record.lifecycle = SetLifecycle::RETIRED;
      record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
      return std::nullopt;
  }
  return OutcomeCode::INTERNAL_ERROR;
}

// ---------------------------------------------------------------------------
// Generations and watermarks
// ---------------------------------------------------------------------------

bool FabricEngine::Impl::advance_set_generation_locked(detail::SetRecord& record) {
  const auto next = record.generation.next();
  if (!next.has_value()) {
    return false;
  }
  record.generation = *next;
  return true;
}

bool FabricEngine::Impl::advance_membership_generation_locked(detail::SetRecord& record) {
  const auto next = record.membership_generation.next();
  if (!next.has_value()) {
    return false;
  }
  record.membership_generation = *next;
  return true;
}

bool FabricEngine::Impl::advance_member_generation_locked(detail::MemberRecord& member) {
  const auto next = member.generation.next();
  if (!next.has_value()) {
    return false;
  }
  member.generation = *next;
  return true;
}

void FabricEngine::Impl::bump_set_watermark_only_locked(detail::SetRecord& record) {
  const auto next = record.invalidation_watermark.next();
  if (next.has_value()) {
    record.invalidation_watermark = *next;
  }
}

void FabricEngine::Impl::bump_set_watermark_locked(detail::SetRecord& record) {
  bump_set_watermark_only_locked(record);
  for (auto& entry : record.members) {
    bump_member_watermark_locked(entry.second);
  }
}

void FabricEngine::Impl::bump_member_watermark_locked(detail::MemberRecord& member) {
  const auto next = member.invalidation_watermark.next();
  if (next.has_value()) {
    member.invalidation_watermark = *next;
  }
}

// ---------------------------------------------------------------------------
// Derived state
// ---------------------------------------------------------------------------

void FabricEngine::Impl::recompute_locked(detail::SetRecord& record) {
  record.usable_member_count = record.recompute_usable_members();
  // Only the derived lifecycle states are recomputed. WITHDRAWING, WITHDRAWN,
  // SUPERSEDED, REVOKED and RETIRED are explicit states and DECLARED is the
  // pre-publication state; none of them may be overwritten by a derivation.
  switch (record.lifecycle) {
    case SetLifecycle::ACTIVE:
    case SetLifecycle::DEGRADED:
    case SetLifecycle::EXHAUSTED:
    case SetLifecycle::ADMIN_DISABLED:
      record.lifecycle = derive_published_lifecycle(record.usable_member_count,
                                                    record.minimum_usable_members,
                                                    record.admin_enabled);
      break;
    default:
      break;
  }
}

void FabricEngine::Impl::reassign_effective_currentness_locked(detail::SetRecord& record) {
  // Nothing derived is cached beyond usable_member_count and lifecycle; this
  // helper exists so that callers read intentionally rather than accidentally.
  recompute_locked(record);
}

// ---------------------------------------------------------------------------
// Path indexes
// ---------------------------------------------------------------------------

void FabricEngine::Impl::index_path_locked(const MultipathSetId& set_id, const PathId& path) {
  path_dependents[path].insert(set_id);
}

void FabricEngine::Impl::unindex_path_locked(const MultipathSetId& set_id, const PathId& path) {
  const auto found = path_dependents.find(path);
  if (found == path_dependents.end()) {
    return;
  }
  found->second.erase(set_id);
  if (found->second.empty()) {
    path_dependents.erase(found);
  }
}

// ---------------------------------------------------------------------------
// History and provenance
// ---------------------------------------------------------------------------

MembershipProvenance FabricEngine::Impl::make_provenance_locked(
    const MutationContext& context, MembershipCause cause,
    const detail::SetRecord& record) const {
  MembershipProvenance provenance;
  provenance.publisher = context.publisher;
  provenance.worker_boot = context.worker_boot;
  provenance.epoch = context.epoch;
  provenance.attempt = context.attempt;
  provenance.set_generation = record.generation;
  provenance.cause = cause;
  return provenance;
}

void FabricEngine::Impl::append_history_locked(detail::SetRecord& record, SetEvent event,
                                               MembershipCause cause,
                                               const MutationContext* context,
                                               std::optional<MultipathMemberId> member_id,
                                               std::optional<PathId> path_id,
                                               std::string summary) {
  detail::HistoryEntry entry;
  entry.set_generation = record.generation;
  entry.event = event;
  entry.cause = cause;
  entry.epoch = context != nullptr ? context->epoch : current_epoch;
  entry.publisher = context != nullptr ? context->publisher : PublisherId{};
  entry.member_id = std::move(member_id);
  entry.path_id = std::move(path_id);
  entry.summary = std::move(summary);
  record.history.push_back(std::move(entry));
  while (record.history.size() > config.limits.max_history_per_set) {
    record.history.erase(record.history.begin());
  }
}

// ---------------------------------------------------------------------------
// Path Authority evaluation
// ---------------------------------------------------------------------------

std::optional<PathAuthorityView> FabricEngine::Impl::lookup_path(const PathId& path) const {
  const std::shared_ptr<const PathAuthoritySource> source = path_authority;
  if (!source) {
    return std::nullopt;
  }
  return source->lookup(path);
}

void FabricEngine::Impl::evaluate_member_locked(detail::SetRecord& record,
                                                detail::MemberRecord& member,
                                                const std::optional<PathAuthorityView>& view,
                                                bool explicit_revalidation) {
  if (member.lifecycle == MemberLifecycle::WITHDRAWN ||
      member.lifecycle == MemberLifecycle::SUPERSEDED ||
      member.lifecycle == MemberLifecycle::RETIRED) {
    // Terminal membership relations are frozen. Their currentness may still be
    // refreshed for explanation purposes, but no lifecycle event is applied.
    if (!member.admin_enabled) {
      member.currentness = MemberCurrentness::ADMIN_DISABLED;
    } else {
      member.currentness = classify_path_authority(view, member.bound_authority_generation,
                                                   record.conditional_authority_permitted);
    }
    return;
  }

  if (view.has_value()) {
    member.observed_authority_generation = view->generation;
    member.observed_authority_state = view->state;
  } else {
    // Path Authority has no record for the path; the previous observation is no
    // longer evidence of anything.
    member.observed_authority_generation.reset();
    member.observed_authority_state.reset();
  }
  MemberCurrentness observed;
  if (!member.admin_enabled) {
    observed = MemberCurrentness::ADMIN_DISABLED;
  } else {
    observed = classify_path_authority(view, member.bound_authority_generation,
                                       record.conditional_authority_permitted);
  }
  if (member.currentness != observed) {
    bump_member_watermark_locked(member);
  }
  member.currentness = observed;

  MemberEvent event = MemberEvent::INPUTS_NOT_USABLE;
  if (observed == MemberCurrentness::CURRENT) {
    event = explicit_revalidation ? MemberEvent::REVALIDATED_OK : MemberEvent::INPUTS_USABLE;
  } else if (currentness_is_revalidation_recoverable(observed)) {
    event = explicit_revalidation ? MemberEvent::REVALIDATED_STALE
                                  : MemberEvent::INPUTS_STALE_AUTHORITY;
  } else {
    event = MemberEvent::INPUTS_NOT_USABLE;
  }
  if (const auto next = member_transition(member.lifecycle, event); next.has_value()) {
    if (*next != member.lifecycle) {
      bump_member_watermark_locked(member);
    }
    member.lifecycle = *next;
  }
}

std::optional<PathAuthorityView> FabricEngine::Impl::observation_of(
    const detail::MemberRecord& member) {
  if (!member.observed_authority_generation.has_value() ||
      !member.observed_authority_state.has_value()) {
    return std::nullopt;
  }
  PathAuthorityView view;
  view.path = member.path_id;
  view.generation = *member.observed_authority_generation;
  view.state = *member.observed_authority_state;
  return view;
}

void FabricEngine::Impl::reevaluate_members_from_observations_locked(
    detail::SetRecord& record) {
  for (auto& entry : record.members) {
    detail::MemberRecord& member = entry.second;
    if (member_is_terminal(member)) {
      continue;
    }
    // A policy change is an explicit administrative act, so members are
    // re-evaluated with the same semantics as an explicit revalidation.
    evaluate_member_locked(record, member, observation_of(member), true);
  }
  recompute_locked(record);
}

std::size_t FabricEngine::Impl::apply_view_locked(const PathId& path,
                                                  const std::optional<PathAuthorityView>& view,
                                                  const MutationContext* context,
                                                  MembershipCause cause) {
  const auto dependents = path_dependents.find(path);
  if (dependents == path_dependents.end()) {
    return 0;
  }
  const std::vector<MultipathSetId> affected(dependents->second.begin(), dependents->second.end());
  std::size_t changed = 0;
  for (const auto& set_id : affected) {
    auto found = sets.find(set_id);
    if (found == sets.end()) {
      continue;
    }
    detail::SetRecord& record = found->second;
    if (record.lifecycle == SetLifecycle::WITHDRAWN ||
        record.lifecycle == SetLifecycle::SUPERSEDED ||
        record.lifecycle == SetLifecycle::REVOKED ||
        record.lifecycle == SetLifecycle::RETIRED) {
      // Terminal governance states are frozen: no late dependency observation
      // may alter a terminal set's recorded state.
      continue;
    }
    // Membership is keyed by PathId, so the exact dependent relation is found
    // without scanning the whole membership table.
    const auto member_entry = record.members.find(path);
    if (member_entry == record.members.end()) {
      continue;
    }
    detail::MemberRecord& member = member_entry->second;
    const MemberLifecycle before_lifecycle = member.lifecycle;
    const MemberCurrentness before_currentness = member.currentness;
    evaluate_member_locked(record, member, view, false);
    const bool set_changed =
        before_lifecycle != member.lifecycle || before_currentness != member.currentness;
    if (!set_changed) {
      continue;
    }
    const SetLifecycle lifecycle_before = record.lifecycle;
    recompute_locked(record);
    if (record.lifecycle != lifecycle_before) {
      // The published governance state changed, so the set generation advances
      // and consumers observe the transition through the ordinary generation
      // mechanism rather than having to diff digests. An exhausted counter
      // (unreachable in practice) leaves the generation unchanged; the semantic
      // digest still covers the new lifecycle.
      if (const auto next = record.generation.next(); next.has_value()) {
        record.generation = *next;
      }
    }
    bump_set_watermark_only_locked(record);
    append_history_locked(record, SetEvent::DEPENDENCY_INVALIDATED, cause, context,
                          std::nullopt, path,
                          "dependency invalidation for path " + path.str() + " -> " +
                              std::string(to_string(record.lifecycle)));
    capture_snapshot_locked(record);
    ++changed;
  }
  return changed;
}

void FabricEngine::Impl::reconcile_path(const PathId& path,
                                        const std::optional<PathAuthorityView>& used) {
  if (!path_authority) {
    return;
  }
  const std::optional<PathAuthorityView> observed = path_authority->lookup(path);
  const bool same = (observed.has_value() == used.has_value()) &&
                    (!observed.has_value() || (*observed == *used));
  if (same) {
    return;
  }
  std::unique_lock<std::shared_mutex> lock(mutex);
  apply_view_locked(path, observed, nullptr, MembershipCause::PATH_INVALIDATED);
}

// ---------------------------------------------------------------------------
// Member consequences of set lifecycle transitions
// ---------------------------------------------------------------------------

void FabricEngine::Impl::apply_member_consequences_locked(detail::SetRecord& record,
                                                          SetLifecycle from, SetLifecycle to,
                                                          const MutationContext* context) {
  (void)from;
  if (from == to) {
    return;
  }
  const bool was_authoritative = (from == SetLifecycle::ACTIVE || from == SetLifecycle::DEGRADED ||
                                  from == SetLifecycle::EXHAUSTED);
  if (!was_authoritative) {
    return;
  }
  MemberEvent member_event = MemberEvent::INPUTS_NOT_USABLE;
  bool apply_event = false;
  switch (to) {
    case SetLifecycle::WITHDRAWING:
    case SetLifecycle::WITHDRAWN:
      member_event = MemberEvent::WITHDRAW;
      apply_event = true;
      break;
    case SetLifecycle::SUPERSEDED:
      member_event = MemberEvent::SUPERSEDE;
      apply_event = true;
      break;
    case SetLifecycle::RETIRED:
      member_event = MemberEvent::RETIRE;
      apply_event = true;
      break;
    case SetLifecycle::REVOKED:
      // Revocation is a set-level authority act. Members keep their own
      // lifecycle; their currentness records that the owning set is not usable.
      for (auto& entry : record.members) {
        if (entry.second.currentness != MemberCurrentness::SET_NOT_USABLE) {
          entry.second.currentness = MemberCurrentness::SET_NOT_USABLE;
          bump_member_watermark_locked(entry.second);
        }
      }
      bump_set_watermark_locked(record);
      record.usable_member_count = record.recompute_usable_members();
      append_history_locked(record, SetEvent::REVOKE, MembershipCause::SET_REVOKED, context,
                            std::nullopt, std::nullopt,
                            "members marked SET_NOT_USABLE by revocation");
      return;
    default:
      return;
  }
  if (!apply_event) {
    return;
  }
  for (auto& entry : record.members) {
    detail::MemberRecord& member = entry.second;
    if (const auto next = member_transition(member.lifecycle, member_event);
        next.has_value()) {
      if (*next != member.lifecycle) {
        bump_member_watermark_locked(member);
      }
      member.lifecycle = *next;
    }
  }
  bump_set_watermark_locked(record);
  // The derived usable count must stay consistent with the member table even
  // for terminal states, where the derived lifecycle is deliberately frozen.
  record.usable_member_count = record.recompute_usable_members();
}

}  // namespace multipath_fabric
