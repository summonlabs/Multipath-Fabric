#include "engine_impl.hpp"

#include <algorithm>
#include <map>
#include <sstream>

namespace multipath_fabric {
namespace {

[[nodiscard]] bool transition_allowed(SetLifecycle state, SetEvent event) noexcept {
  return set_transition(state, event) != SetTransitionAction::REJECT;
}

}  // namespace

// ---------------------------------------------------------------------------
// Whole-set revalidation
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::revalidate_set(const MutationContext& context,
                                           const MultipathSetId& set_id) {
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "revalidate_set requires a set identity");
  }
  const std::vector<std::string> fields{"revalidate_set", set_id.str()};

  // Path Authority lookups happen before the lock is taken.
  const std::vector<PathId> paths = impl_->live_member_paths(set_id);
  std::map<PathId, std::optional<PathAuthorityView>> views;
  for (const auto& path : paths) {
    views.emplace(path, impl_->lookup_path(path));
  }

  FabricOutcome result;
  std::vector<std::optional<PathAuthorityView>> used;
  {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
    if (!authority.succeeded()) {
      return authority;
    }
    if (const auto replay = impl_->attempt_check_locked(context, "revalidate_set", fields);
        replay.has_value()) {
      return *replay;
    }
    detail::SetRecord* record = nullptr;
    const FabricOutcome located = impl_->require_set_locked(set_id, record);
    if (!located.succeeded()) {
      return located;
    }
    if (!transition_allowed(record->lifecycle, SetEvent::REVALIDATE_SET)) {
      return impl_->lifecycle_rejection(record->lifecycle, set_id);
    }
    if (context.expected_set_generation.has_value() &&
        !(record->generation == *context.expected_set_generation)) {
      return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                            "expected set generation " +
                                std::to_string(context.expected_set_generation->value()) +
                                " but the set is at " +
                                std::to_string(record->generation.value()));
    }
    const SetLifecycle before_lifecycle = record->lifecycle;
    const SetCurrentness before_currentness = record->currentness;

    bool complete = true;
    for (auto& entry : record->members) {
      detail::MemberRecord& member = entry.second;
      if (member_is_terminal(member)) {
        continue;
      }
      const auto view = views.find(member.path_id);
      if (view == views.end()) {
        // The member appeared after the lookup pass. It was admitted with a
        // validated binding, so an already-current member is left alone; a
        // member that is not current makes this revalidation incomplete.
        if (member.currentness != MemberCurrentness::CURRENT) {
          complete = false;
        }
        continue;
      }
      if (view->second.has_value()) {
        member.bound_authority_generation = view->second->generation;
      }
      impl_->evaluate_member_locked(*record, member, view->second, true);
    }
    impl_->recompute_locked(*record);
    const SetCurrentness target =
        complete ? SetCurrentness::CURRENT : SetCurrentness::REVALIDATION_REQUIRED;
    const bool changed = (before_lifecycle != record->lifecycle) ||
                         (before_currentness != target);
    record->currentness = target;
    record->governing_epoch = impl_->current_epoch;
    record->authority_generation = impl_->current_authority_generation;
    if (!changed) {
      FabricOutcome outcome = make_outcome(
          OutcomeCode::IDEMPOTENT,
          "revalidation changed nothing; set remains " +
              std::string(to_string(record->lifecycle)) + " with " +
              std::to_string(record->usable_member_count) + " usable member(s)");
      impl_->finalize_outcome_locked(*record, outcome);
      impl_->record_attempt_locked(context, "revalidate_set", fields, outcome);
      return outcome;
    }
    if (!record->generation.next().has_value()) {
      return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                            "multipath set generation is exhausted for " + set_id.str());
    }
    CommitSpec spec;
    spec.event = SetEvent::REVALIDATE_SET;
    spec.cause = MembershipCause::SET_REVALIDATED;
    spec.summary = "revalidated set: " + std::to_string(record->usable_member_count) +
                   " usable of " + std::to_string(record->minimum_usable_members) +
                   " required; lifecycle " + std::string(to_string(before_lifecycle)) + " -> " +
                   std::string(to_string(record->lifecycle)) + "; currentness " +
                   std::string(to_string(before_currentness)) + " -> " +
                   std::string(to_string(record->currentness));
    result = impl_->commit_locked(*record, context, "revalidate_set", fields, spec,
                                  make_outcome(complete ? OutcomeCode::SET_REVALIDATED
                                                        : OutcomeCode::SET_REVALIDATION_INCOMPLETE,
                                               spec.summary));
  }
  for (const auto& path : paths) {
    const auto view = views.find(path);
    impl_->reconcile_path(path, view == views.end() ? std::nullopt : view->second);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Member revalidation
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::revalidate_member(const MutationContext& context,
                                              const MultipathSetId& set_id,
                                              const MultipathMemberId& member_id) {
  if (!set_id.valid() || !member_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "revalidate_member requires a set identity and a member identity");
  }
  const std::vector<std::string> fields{"revalidate_member", set_id.str(), member_id.str()};
  const std::optional<PathId> path = impl_->member_path(set_id, member_id);
  if (!path.has_value()) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
    if (!authority.succeeded()) {
      return authority;
    }
    return make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                          "no member " + member_id.str() + " in set " + set_id.str());
  }
  const std::optional<PathAuthorityView> view = impl_->lookup_path(*path);

  FabricOutcome result;
  {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
    if (!authority.succeeded()) {
      return authority;
    }
    if (const auto replay = impl_->attempt_check_locked(context, "revalidate_member", fields);
        replay.has_value()) {
      return *replay;
    }
    detail::SetRecord* record = nullptr;
    const FabricOutcome located = impl_->require_set_locked(set_id, record);
    if (!located.succeeded()) {
      return located;
    }
    const auto path_entry = record->member_index.find(member_id);
    if (path_entry == record->member_index.end()) {
      return make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                            "no member " + member_id.str() + " in set " + set_id.str());
    }
    if (!transition_allowed(record->lifecycle, SetEvent::MEMBERSHIP_RECHECK)) {
      return impl_->lifecycle_rejection(record->lifecycle, set_id);
    }
    detail::MemberRecord& member = record->members.at(path_entry->second);
    if (member_is_terminal(member)) {
      return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                            "member " + member_id.str() + " is " +
                                std::string(to_string(member.lifecycle)) +
                                " and cannot be revalidated");
    }
    if (context.expected_set_generation.has_value() &&
        !(record->generation == *context.expected_set_generation)) {
      return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                            "expected set generation " +
                                std::to_string(context.expected_set_generation->value()) +
                                " but the set is at " +
                                std::to_string(record->generation.value()));
    }
    if (context.expected_member_generation.has_value() &&
        !(member.generation == *context.expected_member_generation)) {
      return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                            "expected member generation " +
                                std::to_string(context.expected_member_generation->value()) +
                                " but the member is at " +
                                std::to_string(member.generation.value()));
    }
    if (!member.generation.next().has_value() || !record->generation.next().has_value()) {
      return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                            "generation exhausted for set " + set_id.str());
    }

    const MemberLifecycle before_lifecycle = member.lifecycle;
    const MemberCurrentness before_currentness = member.currentness;
    const PathAuthorityGeneration before_generation = member.bound_authority_generation;
    if (view.has_value()) {
      // Explicit revalidation rebinds the member to the generation Path
      // Authority reports right now. A binding is never advanced silently.
      member.bound_authority_generation = view->generation;
    }
    impl_->evaluate_member_locked(*record, member, view, true);
    const bool changed = before_lifecycle != member.lifecycle ||
                         before_currentness != member.currentness ||
                         !(before_generation == member.bound_authority_generation);
    if (changed) {
      const auto advanced = member.generation.next();
      if (advanced.has_value()) {
        member.generation = *advanced;
      }
      impl_->bump_member_watermark_locked(member);
    }
    impl_->recompute_locked(*record);
    if (!changed) {
      const bool usable_now = member_inputs_usable(member);
      FabricOutcome outcome = make_outcome(
          usable_now ? OutcomeCode::IDEMPOTENT : OutcomeCode::MEMBER_REVALIDATION_NEGATIVE,
          "member " + member_id.str() + " revalidation changed nothing; member remains " +
              std::string(to_string(member.lifecycle)) + " currentness " +
              std::string(to_string(member.currentness)));
      impl_->finalize_outcome_locked(*record, outcome);
      outcome.member_id = member_id;
      outcome.member_generation = member.generation;
      outcome.path_id = member.path_id;
      impl_->record_attempt_locked(context, "revalidate_member", fields, outcome);
      return outcome;
    }
    CommitSpec spec;
    spec.event = SetEvent::MEMBERSHIP_RECHECK;
    spec.cause = MembershipCause::MEMBER_REVALIDATED;
    spec.member_id = member_id;
    spec.path_id = member.path_id;
    std::ostringstream summary;
    summary << "revalidated member " << member_id.str() << " (path " << member.path_id.view()
            << ") binding " << before_generation.value() << " -> "
            << member.bound_authority_generation.value() << "; lifecycle "
            << to_string(before_lifecycle) << " -> " << to_string(member.lifecycle)
            << "; currentness " << to_string(before_currentness) << " -> "
            << to_string(member.currentness);
    spec.summary = summary.str();
    const bool usable = member_inputs_usable(member);
    FabricOutcome outcome =
        make_outcome(usable ? OutcomeCode::MEMBER_REVALIDATED
                            : OutcomeCode::MEMBER_REVALIDATION_NEGATIVE,
                     spec.summary);
    outcome.member_id = member_id;
    outcome.member_generation = member.generation;
    outcome.path_id = member.path_id;
    result = impl_->commit_locked(*record, context, "revalidate_member", fields, spec, outcome);
  }
  impl_->reconcile_path(*path, view);
  return result;
}

// ---------------------------------------------------------------------------
// Two-phase member revalidation
// ---------------------------------------------------------------------------

RevalidationBegin FabricEngine::begin_member_revalidation(const MutationContext& context,
                                                          const MultipathSetId& set_id,
                                                          const MultipathMemberId& member_id,
                                                          const RevalidationAttemptId& attempt) {
  RevalidationBegin begin;
  if (!set_id.valid() || !member_id.valid() || !attempt.valid()) {
    begin.outcome = make_rejection(OutcomeCode::MALFORMED_REQUEST,
                                   "begin_member_revalidation requires a set, a member and a "
                                   "revalidation attempt identity");
    return begin;
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    begin.outcome = authority;
    return begin;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    begin.outcome = located;
    return begin;
  }
  const auto path_entry = record->member_index.find(member_id);
  if (path_entry == record->member_index.end()) {
    begin.outcome = make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                                   "no member " + member_id.str() + " in set " + set_id.str());
    return begin;
  }
  detail::MemberRecord& member = record->members.at(path_entry->second);
  if (member_is_terminal(member)) {
    begin.outcome = make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                                   "member " + member_id.str() + " is " +
                                       std::string(to_string(member.lifecycle)) +
                                       " and cannot be revalidated");
    return begin;
  }
  if (member.pending_revalidations >=
      impl_->config.limits.max_pending_revalidations_per_set) {
    begin.outcome = make_rejection(
        OutcomeCode::RESOURCE_LIMIT,
        "max_pending_revalidations_per_set limit of " +
            std::to_string(impl_->config.limits.max_pending_revalidations_per_set) + " reached");
    return begin;
  }
  const auto next_pending = detail::checked_add(member.pending_revalidations, 1);
  if (!next_pending.has_value()) {
    begin.outcome = make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                                   "pending revalidation counter is exhausted");
    return begin;
  }
  member.pending_revalidations = static_cast<std::uint32_t>(*next_pending);

  RevalidationTicket ticket;
  ticket.set_id = set_id;
  ticket.member_id = member_id;
  ticket.attempt = attempt;
  ticket.member_generation = member.generation;
  ticket.set_watermark = record->invalidation_watermark;
  ticket.member_watermark = member.invalidation_watermark;
  ticket.epoch = impl_->current_epoch;
  ticket.bound_authority_generation = member.bound_authority_generation;
  ticket.valid = true;
  begin.ticket = ticket;
  begin.outcome = make_outcome(OutcomeCode::OK,
                               "revalidation ticket issued for member " + member_id.str() +
                                   " at watermark " +
                                   std::to_string(member.invalidation_watermark.value()));
  return begin;
}

FabricOutcome FabricEngine::complete_member_revalidation(
    const MutationContext& context, const RevalidationTicket& ticket,
    const std::optional<PathAuthorityView>& current) {
  if (!ticket.valid) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "revalidation ticket is not valid");
  }
  if (!ticket.set_id.valid() || !ticket.member_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "revalidation ticket is missing an identity");
  }
  const std::vector<std::string> fields{"complete_member_revalidation", ticket.set_id.str(),
                                        ticket.member_id.str(), ticket.attempt.str()};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority =
      impl_->authority_check_locked(context, std::nullopt, ticket.set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(ticket.set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  const auto path_entry = record->member_index.find(ticket.member_id);
  if (path_entry == record->member_index.end()) {
    return make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                          "no member " + ticket.member_id.str() + " in set " +
                              ticket.set_id.str());
  }
  detail::MemberRecord& member = record->members.at(path_entry->second);
  if (member.pending_revalidations == 0) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "no revalidation is pending for member " + ticket.member_id.str());
  }
  const auto release = [&member]() {
    if (member.pending_revalidations > 0) {
      --member.pending_revalidations;
    }
  };
  // Stale-completion defense: any change to the set or the member inputs since
  // the ticket was issued invalidates the completion.
  if (!(record->invalidation_watermark == ticket.set_watermark) ||
      !(member.invalidation_watermark == ticket.member_watermark)) {
    release();
    std::ostringstream stream;
    stream << "revalidation ticket is stale: issued at set watermark "
           << ticket.set_watermark.value() << "/member watermark "
           << ticket.member_watermark.value() << " but the member is now at "
           << record->invalidation_watermark.value() << '/'
           << member.invalidation_watermark.value();
    return make_rejection(OutcomeCode::STALE_REVALIDATION, stream.str());
  }
  if (!(ticket.epoch == impl_->current_epoch)) {
    release();
    return make_rejection(OutcomeCode::STALE_EPOCH,
                          "revalidation ticket was issued at epoch " +
                              std::to_string(ticket.epoch.value()) +
                              " but the governing epoch is now " +
                              std::to_string(impl_->current_epoch.value()));
  }
  if (context.expected_member_generation.has_value() &&
      !(member.generation == *context.expected_member_generation)) {
    release();
    return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                          "expected member generation " +
                              std::to_string(context.expected_member_generation->value()) +
                              " but the member is at " +
                              std::to_string(member.generation.value()));
  }
  if (member_is_terminal(member)) {
    release();
    return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                          "member " + ticket.member_id.str() + " became " +
                              std::string(to_string(member.lifecycle)) +
                              " while revalidation was in flight");
  }
  if (!member.generation.next().has_value() || !record->generation.next().has_value()) {
    release();
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "generation exhausted for set " + ticket.set_id.str());
  }

  const MemberLifecycle before_lifecycle = member.lifecycle;
  const MemberCurrentness before_currentness = member.currentness;
  const PathAuthorityGeneration before_generation = member.bound_authority_generation;
  if (current.has_value()) {
    member.bound_authority_generation = current->generation;
  }
  impl_->evaluate_member_locked(*record, member, current, true);
  release();
  const bool changed = before_lifecycle != member.lifecycle ||
                       before_currentness != member.currentness ||
                       !(before_generation == member.bound_authority_generation);
  if (changed) {
    const auto advanced = member.generation.next();
    if (advanced.has_value()) {
      member.generation = *advanced;
    }
    impl_->bump_member_watermark_locked(member);
  }
  impl_->recompute_locked(*record);

  CommitSpec spec;
  spec.advance_set_generation = changed;
  spec.event = SetEvent::MEMBERSHIP_RECHECK;
  spec.cause = MembershipCause::MEMBER_REVALIDATED;
  spec.member_id = ticket.member_id;
  spec.path_id = member.path_id;
  std::ostringstream summary;
  summary << "completed two-phase revalidation " << ticket.attempt.view() << " for member "
          << ticket.member_id.view() << "; binding " << before_generation.value() << " -> "
          << member.bound_authority_generation.value() << "; lifecycle "
          << to_string(before_lifecycle) << " -> " << to_string(member.lifecycle);
  spec.summary = summary.str();
  if (!changed) {
    const bool usable_now = member_inputs_usable(member);
    FabricOutcome outcome =
        make_outcome(usable_now ? OutcomeCode::IDEMPOTENT
                                : OutcomeCode::MEMBER_REVALIDATION_NEGATIVE,
                     spec.summary);
    impl_->finalize_outcome_locked(*record, outcome);
    outcome.member_id = ticket.member_id;
    outcome.member_generation = member.generation;
    outcome.path_id = member.path_id;
    impl_->record_attempt_locked(context, "complete_member_revalidation", fields, outcome);
    return outcome;
  }
  const bool usable = member_inputs_usable(member);
  FabricOutcome outcome =
      make_outcome(usable ? OutcomeCode::MEMBER_REVALIDATED
                          : OutcomeCode::MEMBER_REVALIDATION_NEGATIVE,
                   spec.summary);
  outcome.member_id = ticket.member_id;
  outcome.member_generation = member.generation;
  outcome.path_id = member.path_id;
  return impl_->commit_locked(*record, context, "complete_member_revalidation", fields, spec,
                              outcome);
}

FabricOutcome FabricEngine::abandon_member_revalidation(const RevalidationTicket& ticket) {
  if (!ticket.valid) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "revalidation ticket is not valid");
  }
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto set = impl_->sets.find(ticket.set_id);
  if (set == impl_->sets.end()) {
    return make_rejection(OutcomeCode::SET_NOT_FOUND,
                          "no such set: " + ticket.set_id.str());
  }
  const auto path_entry = set->second.member_index.find(ticket.member_id);
  if (path_entry == set->second.member_index.end()) {
    return make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                          "no member " + ticket.member_id.str() + " in set " +
                              ticket.set_id.str());
  }
  detail::MemberRecord& member = set->second.members.at(path_entry->second);
  if (member.pending_revalidations == 0) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "no revalidation is pending for member " + ticket.member_id.str());
  }
  --member.pending_revalidations;
  return make_outcome(OutcomeCode::OK,
                      "abandoned revalidation ticket " + ticket.attempt.str());
}

// ---------------------------------------------------------------------------
// Dependency invalidation
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::apply_path_authority(const MutationContext& context,
                                                 const PathAuthorityView& view) {
  if (!view.path.valid() || !view.generation.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "apply_path_authority requires a valid path and generation");
  }
  const std::vector<std::string> fields{"apply_path_authority", view.path.str(),
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
  if (const auto replay = impl_->attempt_check_locked(context, "apply_path_authority", fields);
      replay.has_value()) {
    return *replay;
  }
  // Every dependent set must be inside the caller's authority scope.
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
  const std::size_t changed = impl_->apply_view_locked(
      view.path, std::optional<PathAuthorityView>(view), &context,
      MembershipCause::PATH_INVALIDATED);
  std::ostringstream detail;
  detail << "applied Path Authority view for " << view.path.view() << " generation "
         << view.generation.value() << " state " << to_string(view.state) << "; "
         << changed << " dependent set(s) changed";
  FabricOutcome outcome = make_outcome(OutcomeCode::PATH_INVALIDATED, detail.str());
  outcome.path_id = view.path;
  impl_->record_attempt_locked(context, "apply_path_authority", fields, outcome);
  return outcome;
}

FabricOutcome FabricEngine::refresh_path(const MutationContext& context, const PathId& path) {
  if (!path.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "refresh_path requires a valid path identity");
  }
  const std::optional<PathAuthorityView> view = impl_->lookup_path(path);
  if (!view.has_value()) {
    return make_rejection(OutcomeCode::PATH_AUTHORITY_UNKNOWN,
                          "Path Authority has no record for path " + path.str() +
                              (impl_->path_authority ? "" : " (no Path Authority source bound)"));
  }
  return apply_path_authority(context, *view);
}

}  // namespace multipath_fabric
