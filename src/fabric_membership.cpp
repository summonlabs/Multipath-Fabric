#include "engine_impl.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {
namespace {

[[nodiscard]] bool transition_allowed(SetLifecycle state, SetEvent event) noexcept {
  return set_transition(state, event) != SetTransitionAction::REJECT;
}

[[nodiscard]] std::string member_fields(const std::string& operation,
                                        const MultipathSetId& set_id, const PathId& path,
                                        PathAuthorityGeneration generation) {
  return operation + "|" + set_id.str() + "|" + path.str() + "|" +
         std::to_string(generation.value());
}

[[nodiscard]] std::vector<std::string> bulk_fields(const std::string& operation,
                                                   const MultipathSetId& set_id,
                                                   const std::vector<MemberRequest>& requests) {
  std::vector<std::string> fields;
  fields.reserve(requests.size() + 2);
  fields.push_back(operation);
  fields.push_back(set_id.str());
  for (const auto& request : requests) {
    fields.push_back(member_fields(operation, set_id, request.path_id,
                                   request.authority_generation));
  }
  return fields;
}

}  // namespace

// ---------------------------------------------------------------------------
// Membership publication (single and bulk share one implementation)
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::add_member(const MutationContext& context,
                                       const MultipathSetId& set_id, const PathId& path_id,
                                       const PathAuthorityGeneration& authority_generation) {
  std::vector<MemberRequest> requests(1);
  requests[0].path_id = path_id;
  requests[0].authority_generation = authority_generation;
  return add_members_internal(context, set_id, requests, "add_member", false);
}

FabricOutcome FabricEngine::add_members(const MutationContext& context,
                                        const MultipathSetId& set_id,
                                        const std::vector<MemberRequest>& requests) {
  return add_members_internal(context, set_id, requests, "add_members", true);
}

FabricOutcome FabricEngine::add_members_internal(const MutationContext& context,
                                                 const MultipathSetId& set_id,
                                                 const std::vector<MemberRequest>& requests,
                                                 std::string_view operation, bool bulk) {
  const std::string operation_name(operation);
  if (!set_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          operation_name + " requires a set identity");
  }
  if (requests.empty()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          operation_name + " requires at least one member request");
  }
  if (bulk && requests.size() > impl_->config.limits.max_batch_size) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "batch of " + std::to_string(requests.size()) +
                              " exceeds max_batch_size " +
                              std::to_string(impl_->config.limits.max_batch_size));
  }
  for (const auto& request : requests) {
    if (!request.path_id.valid() || !request.authority_generation.valid()) {
      return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                            "member request requires a valid PathId and PathAuthorityGeneration");
    }
  }

  // Path Authority lookups happen outside the engine lock.
  std::vector<std::optional<PathAuthorityView>> views;
  views.reserve(requests.size());
  for (const auto& request : requests) {
    views.push_back(impl_->lookup_path(request.path_id));
  }
  const std::vector<std::string> fields = bulk_fields(operation_name, set_id, requests);

  FabricOutcome result;
  {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex);
    const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
    if (!authority.succeeded()) {
      return authority;
    }
    if (const auto replay = impl_->attempt_check_locked(context, operation_name, fields);
        replay.has_value()) {
      return *replay;
    }
    detail::SetRecord* record = nullptr;
    const FabricOutcome located = impl_->require_set_locked(set_id, record);
    if (!located.succeeded()) {
      return located;
    }
    // Stage 7: lifecycle admissibility for the membership-add event.
    if (!transition_allowed(record->lifecycle, SetEvent::MEMBER_ADDED)) {
      return impl_->lifecycle_rejection(record->lifecycle, set_id);
    }
    // Stage 8: expected generation.
    if (context.expected_set_generation.has_value() &&
        !(record->generation == *context.expected_set_generation)) {
      return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                            "expected set generation " +
                                std::to_string(context.expected_set_generation->value()) +
                                " but the set is at " +
                                std::to_string(record->generation.value()));
    }
    // Stage 9: exact Path Authority generation and state for every member.
    for (std::size_t i = 0; i < requests.size(); ++i) {
      const MemberCurrentness currentness =
          classify_path_authority(views[i], requests[i].authority_generation,
                                  record->conditional_authority_permitted);
      if (currentness != MemberCurrentness::CURRENT) {
        return impl_->currentness_rejection(currentness, requests[i].path_id);
      }
    }
    // Stage 11 (evaluated early because it decides how many slots are consumed):
    // duplicate membership. A live relation for the same exact path is refused;
    // a terminal relation is replaced in place and the lineage is recorded.
    std::size_t new_live = 0;
    std::vector<bool> replaces(requests.size(), false);
    {
      std::vector<PathId> seen;
      for (std::size_t i = 0; i < requests.size(); ++i) {
        const PathId& path = requests[i].path_id;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) {
          return make_rejection(OutcomeCode::DUPLICATE_MEMBER,
                                "path " + path.str() +
                                    " appears more than once in the same batch");
        }
        seen.push_back(path);
        const auto existing = record->members.find(path);
        if (existing == record->members.end()) {
          ++new_live;
          continue;
        }
        if (!member_is_terminal(existing->second)) {
          return make_rejection(OutcomeCode::DUPLICATE_MEMBER,
                                "path " + path.str() + " is already a live member " +
                                    existing->second.id.str() + " of set " + set_id.str());
        }
        replaces[i] = true;
      }
    }
    // Stage 10: resource limits.
    const std::uint64_t live = live_member_count(*record);
    if (live + new_live > impl_->config.limits.max_members_per_set) {
      return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                            "max_members_per_set limit of " +
                                std::to_string(impl_->config.limits.max_members_per_set) +
                                " would be exceeded by set " + set_id.str());
    }
    if (impl_->total_members + new_live > impl_->config.limits.max_total_members) {
      return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                            "max_total_members limit of " +
                                std::to_string(impl_->config.limits.max_total_members) +
                                " would be exceeded");
    }
    for (std::size_t i = 0; i < requests.size(); ++i) {
      if (replaces[i]) {
        continue;
      }
      const auto dependents = impl_->path_dependents.find(requests[i].path_id);
      if (dependents != impl_->path_dependents.end() &&
          dependents->second.size() >= impl_->config.limits.max_path_dependencies_per_path) {
        return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                              "max_path_dependencies_per_path limit of " +
                                  std::to_string(
                                      impl_->config.limits.max_path_dependencies_per_path) +
                                  " reached for path " + requests[i].path_id.str());
      }
    }
    if (!record->generation.next().has_value() ||
        !record->membership_generation.next().has_value()) {
      return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                            "generation exhausted for set " + set_id.str());
    }

    // Commit: every validated member is applied as one semantic transaction.
    const SetLifecycle before = record->lifecycle;
    const auto transition = impl_->apply_transition_locked(*record, SetEvent::MEMBER_ADDED);
    if (transition.has_value()) {
      return impl_->lifecycle_rejection(before, set_id);
    }
    std::vector<MultipathMemberId> added_ids;
    added_ids.reserve(requests.size());
    for (std::size_t i = 0; i < requests.size(); ++i) {
      const PathId& path = requests[i].path_id;
      detail::MemberRecord member;
      member.id = impl_->ids.next_member_id();
      member.path_id = path;
      member.bound_authority_generation = requests[i].authority_generation;
      member.generation = MultipathMemberGeneration::first();
      member.admin_enabled = true;
      member.provenance =
          impl_->make_provenance_locked(context, MembershipCause::MEMBER_ADDED, *record);
      member.lifecycle = MemberLifecycle::PENDING;
      member.currentness = MemberCurrentness::PENDING_EVALUATION;
      impl_->evaluate_member_locked(*record, member, views[i], false);

      const auto existing = record->members.find(path);
      if (existing != record->members.end()) {
        member.predecessor = existing->second.id;
        record->member_index.erase(existing->second.id);
      }
      added_ids.push_back(member.id);
      record->member_index[member.id] = path;
      record->members[path] = std::move(member);
      impl_->index_path_locked(set_id, path);
    }
    impl_->total_members += new_live;
    impl_->recompute_locked(*record);

    std::ostringstream summary;
    summary << (bulk ? "bulk published " : "added ") << requests.size() << " member(s):";
    for (const auto& request : requests) {
      summary << ' ' << request.path_id.view() << '@' << request.authority_generation.value();
    }
    summary << "; lifecycle " << to_string(before) << " -> " << to_string(record->lifecycle);

    CommitSpec spec;
    spec.advance_membership_generation = true;
    spec.event = SetEvent::MEMBER_ADDED;
    spec.cause = MembershipCause::MEMBER_ADDED;
    spec.member_id = added_ids.size() == 1 ? std::optional<MultipathMemberId>(added_ids.front())
                                           : std::nullopt;
    spec.path_id = requests.size() == 1 ? std::optional<PathId>(requests.front().path_id)
                                        : std::nullopt;
    spec.summary = summary.str();
    FabricOutcome added = make_outcome(OutcomeCode::MEMBER_ADDED, spec.summary);
    if (added_ids.size() == 1) {
      added.member_id = added_ids.front();
    }
    if (requests.size() == 1) {
      added.path_id = requests.front().path_id;
    }
    result = impl_->commit_locked(*record, context, operation_name, fields, spec, added);
  }

  // Post-commit reconciliation closes the window between the Path Authority
  // lookup and the commit: if the source changed while the mutation was in
  // flight, the observed view is applied immediately so the durable state
  // converges on the truth instead of silently keeping a stale binding.
  for (std::size_t i = 0; i < requests.size(); ++i) {
    impl_->reconcile_path(requests[i].path_id, views[i]);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Member removal, withdrawal, replacement and administrative state
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::remove_member(const MutationContext& context,
                                          const MultipathSetId& set_id,
                                          const MultipathMemberId& member_id,
                                          std::string reason) {
  if (!set_id.valid() || !member_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "remove_member requires a set identity and a member identity");
  }
  if (reason.size() > 256) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "removal reason exceeds the 256 character bound");
  }
  const std::vector<std::string> fields{"remove_member", set_id.str(), member_id.str(), reason};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "remove_member", fields);
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
  if (!transition_allowed(record->lifecycle, SetEvent::MEMBER_REMOVED)) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  const PathId path = path_entry->second;
  const auto member_entry = record->members.find(path);
  if (member_entry == record->members.end()) {
    return make_rejection(OutcomeCode::INTERNAL_ERROR,
                          "member index and membership table disagree for " + member_id.str());
  }
  if (context.expected_set_generation.has_value() &&
      !(record->generation == *context.expected_set_generation)) {
    return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                          "expected set generation " +
                              std::to_string(context.expected_set_generation->value()) +
                              " but the set is at " + std::to_string(record->generation.value()));
  }
  if (context.expected_member_generation.has_value() &&
      !(member_entry->second.generation == *context.expected_member_generation)) {
    return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                          "expected member generation " +
                              std::to_string(context.expected_member_generation->value()) +
                              " but the member is at " +
                              std::to_string(member_entry->second.generation.value()));
  }
  if (!record->generation.next().has_value() ||
      !record->membership_generation.next().has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "generation exhausted for set " + set_id.str());
  }
  const SetLifecycle before = record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::MEMBER_REMOVED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  // The resulting state is durable before the historical relation is dropped:
  // the removal is captured in bounded history and in the snapshot that the
  // commit produces, so recovery never depends on the erased record.
  record->member_index.erase(path_entry);
  record->members.erase(member_entry);
  impl_->unindex_path_locked(set_id, path);
  if (impl_->total_members > 0) {
    --impl_->total_members;
  }
  impl_->recompute_locked(*record);

  CommitSpec spec;
  spec.advance_membership_generation = true;
  spec.event = SetEvent::MEMBER_REMOVED;
  spec.cause = MembershipCause::MEMBER_REMOVED;
  spec.member_id = member_id;
  spec.path_id = path;
  spec.summary = "removed member " + member_id.str() + " (path " + path.str() + "): " + reason;
  FabricOutcome removed = make_outcome(OutcomeCode::MEMBER_REMOVED, spec.summary);
  removed.member_id = member_id;
  removed.path_id = path;
  return impl_->commit_locked(*record, context, "remove_member", fields, spec, removed);
}

FabricOutcome FabricEngine::withdraw_member(const MutationContext& context,
                                            const MultipathSetId& set_id,
                                            const MultipathMemberId& member_id,
                                            std::string reason) {
  if (!set_id.valid() || !member_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "withdraw_member requires a set identity and a member identity");
  }
  if (reason.size() > 256) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "withdrawal reason exceeds the 256 character bound");
  }
  const std::vector<std::string> fields{"withdraw_member", set_id.str(), member_id.str(), reason};
  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "withdraw_member", fields);
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
  if (!transition_allowed(record->lifecycle, SetEvent::MEMBER_REMOVED)) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  detail::MemberRecord& member = record->members.at(path_entry->second);
  if (member.lifecycle == MemberLifecycle::WITHDRAWN) {
    FabricOutcome outcome =
        make_outcome(OutcomeCode::IDEMPOTENT, "member " + member_id.str() + " is already withdrawn");
    impl_->finalize_outcome_locked(*record, outcome);
    impl_->record_attempt_locked(context, "withdraw_member", fields, outcome);
    return outcome;
  }
  if (context.expected_member_generation.has_value() &&
      !(member.generation == *context.expected_member_generation)) {
    return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                          "expected member generation " +
                              std::to_string(context.expected_member_generation->value()) +
                              " but the member is at " +
                              std::to_string(member.generation.value()));
  }
  const auto next_member_generation = member.generation.next();
  if (!next_member_generation.has_value() || !record->generation.next().has_value() ||
      !record->membership_generation.next().has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "generation exhausted for set " + set_id.str());
  }
  const auto next_lifecycle = member_transition(member.lifecycle, MemberEvent::WITHDRAW);
  if (!next_lifecycle.has_value()) {
    return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                          "member " + member_id.str() + " cannot be withdrawn from lifecycle " +
                              std::string(to_string(member.lifecycle)));
  }
  const SetLifecycle before = record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::MEMBER_REMOVED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }
  const PathId path = member.path_id;
  member.lifecycle = *next_lifecycle;
  member.currentness = MemberCurrentness::SET_NOT_USABLE;
  member.generation = *next_member_generation;
  impl_->bump_member_watermark_locked(member);
  impl_->recompute_locked(*record);

  CommitSpec spec;
  spec.advance_membership_generation = true;
  spec.event = SetEvent::MEMBER_REMOVED;
  spec.cause = MembershipCause::MEMBER_REMOVED;
  spec.member_id = member_id;
  spec.path_id = path;
  spec.summary = "withdrew member " + member_id.str() + " (path " + path.str() + "): " + reason;
  FabricOutcome withdrawn = make_outcome(OutcomeCode::MEMBER_WITHDRAWN, spec.summary);
  withdrawn.member_id = member_id;
  withdrawn.path_id = path;
  return impl_->commit_locked(*record, context, "withdraw_member", fields, spec, withdrawn);
}

FabricOutcome FabricEngine::replace_member(const MutationContext& context,
                                           const MultipathSetId& set_id,
                                           const MultipathMemberId& member_id,
                                           const PathId& successor_path,
                                           const PathAuthorityGeneration& successor_generation,
                                           std::string reason) {
  if (!set_id.valid() || !member_id.valid() || !successor_path.valid() ||
      !successor_generation.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "replace_member requires a set, a member, a successor PathId and a "
                          "successor PathAuthorityGeneration");
  }
  if (reason.size() > 256) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "replacement reason exceeds the 256 character bound");
  }
  const std::vector<std::string> fields{"replace_member",  set_id.str(),
                                        member_id.str(),   successor_path.str(),
                                        std::to_string(successor_generation.value()), reason};
  const std::optional<PathAuthorityView> view = impl_->lookup_path(successor_path);

  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay = impl_->attempt_check_locked(context, "replace_member", fields);
      replay.has_value()) {
    return *replay;
  }
  detail::SetRecord* record = nullptr;
  const FabricOutcome located = impl_->require_set_locked(set_id, record);
  if (!located.succeeded()) {
    return located;
  }
  if (!transition_allowed(record->lifecycle, SetEvent::MEMBER_REPLACED)) {
    return impl_->lifecycle_rejection(record->lifecycle, set_id);
  }
  const auto path_entry = record->member_index.find(member_id);
  if (path_entry == record->member_index.end()) {
    return make_rejection(OutcomeCode::MEMBER_NOT_FOUND,
                          "no member " + member_id.str() + " in set " + set_id.str());
  }
  const PathId predecessor_path = path_entry->second;
  if (predecessor_path == successor_path) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "successor path equals the predecessor path; use revalidate_member to "
                          "rebind the Path Authority generation of an existing member");
  }
  if (context.expected_set_generation.has_value() &&
      !(record->generation == *context.expected_set_generation)) {
    return make_rejection(OutcomeCode::STALE_SET_GENERATION,
                          "expected set generation " +
                              std::to_string(context.expected_set_generation->value()) +
                              " but the set is at " + std::to_string(record->generation.value()));
  }
  detail::MemberRecord& predecessor = record->members.at(predecessor_path);
  if (context.expected_member_generation.has_value() &&
      !(predecessor.generation == *context.expected_member_generation)) {
    return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                          "expected member generation " +
                              std::to_string(context.expected_member_generation->value()) +
                              " but the member is at " +
                              std::to_string(predecessor.generation.value()));
  }
  const MemberCurrentness currentness =
      classify_path_authority(view, successor_generation, record->conditional_authority_permitted);
  if (currentness != MemberCurrentness::CURRENT) {
    return impl_->currentness_rejection(currentness, successor_path);
  }
  const auto existing_successor = record->members.find(successor_path);
  if (existing_successor != record->members.end() && !member_is_terminal(existing_successor->second)) {
    return make_rejection(OutcomeCode::DUPLICATE_MEMBER,
                          "successor path " + successor_path.str() + " is already a live member " +
                              existing_successor->second.id.str());
  }
  const std::uint64_t live = live_member_count(*record);
  const std::uint64_t freed = member_is_terminal(predecessor) ? 0U : 1U;
  const std::uint64_t consumed =
      (existing_successor == record->members.end() || member_is_terminal(existing_successor->second))
          ? 1U
          : 0U;
  if (live + consumed - freed > impl_->config.limits.max_members_per_set) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "max_members_per_set limit of " +
                              std::to_string(impl_->config.limits.max_members_per_set) +
                              " would be exceeded by replacement in set " + set_id.str());
  }
  if (consumed > 0 && impl_->total_members >= impl_->config.limits.max_total_members) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "max_total_members limit of " +
                              std::to_string(impl_->config.limits.max_total_members) +
                              " would be exceeded by replacement");
  }
  if (consumed > 0) {
    const auto dependents = impl_->path_dependents.find(successor_path);
    if (dependents != impl_->path_dependents.end() &&
        dependents->second.size() >= impl_->config.limits.max_path_dependencies_per_path) {
      return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                            "max_path_dependencies_per_path limit reached for path " +
                                successor_path.str());
    }
  }
  if (!record->generation.next().has_value() ||
      !record->membership_generation.next().has_value() ||
      !predecessor.generation.next().has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "generation exhausted for set " + set_id.str());
  }

  const SetLifecycle before = record->lifecycle;
  if (const auto rejection = impl_->apply_transition_locked(*record, SetEvent::MEMBER_REPLACED);
      rejection.has_value()) {
    return impl_->lifecycle_rejection(before, set_id);
  }

  detail::MemberRecord successor;
  successor.id = impl_->ids.next_member_id();
  successor.path_id = successor_path;
  successor.bound_authority_generation = successor_generation;
  successor.generation = MultipathMemberGeneration::first();
  successor.admin_enabled = true;
  successor.predecessor = member_id;
  successor.provenance =
      impl_->make_provenance_locked(context, MembershipCause::MEMBER_REPLACED, *record);
  successor.lifecycle = MemberLifecycle::PENDING;
  successor.currentness = MemberCurrentness::PENDING_EVALUATION;
  impl_->evaluate_member_locked(*record, successor, view, false);

  predecessor.lifecycle = MemberLifecycle::SUPERSEDED;
  predecessor.currentness = MemberCurrentness::SET_NOT_USABLE;
  predecessor.successor = successor.id;
  const auto advanced = predecessor.generation.next();
  if (advanced.has_value()) {
    predecessor.generation = *advanced;
  }
  impl_->bump_member_watermark_locked(predecessor);

  if (existing_successor != record->members.end()) {
    record->member_index.erase(existing_successor->second.id);
  }
  const MultipathMemberId successor_id = successor.id;
  record->member_index[successor_id] = successor_path;
  record->members[successor_path] = std::move(successor);
  impl_->index_path_locked(set_id, successor_path);
  if (consumed > 0) {
    ++impl_->total_members;
  }
  impl_->recompute_locked(*record);

  CommitSpec spec;
  spec.advance_membership_generation = true;
  spec.event = SetEvent::MEMBER_REPLACED;
  spec.cause = MembershipCause::MEMBER_REPLACED;
  spec.member_id = successor_id;
  spec.path_id = successor_path;
  spec.summary = "replaced member " + member_id.str() + " (path " + predecessor_path.str() +
                 ") with member " + successor_id.str() + " (path " + successor_path.str() +
                 "@" + std::to_string(successor_generation.value()) + "): " + reason;
  return impl_->commit_locked(*record, context, "replace_member", fields, spec,
                              make_outcome(OutcomeCode::MEMBER_REPLACED, spec.summary));
}

FabricOutcome FabricEngine::set_member_admin_enabled(const MutationContext& context,
                                                     const MultipathSetId& set_id,
                                                     const MultipathMemberId& member_id,
                                                     bool enabled) {
  if (!set_id.valid() || !member_id.valid()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                          "set_member_admin_enabled requires a set and a member identity");
  }
  const std::vector<std::string> fields{"set_member_admin_enabled", set_id.str(), member_id.str(),
                                        enabled ? "1" : "0"};
  const std::optional<PathId> path = impl_->member_path(set_id, member_id);
  const std::optional<PathAuthorityView> view =
      path.has_value() ? impl_->lookup_path(*path) : std::nullopt;

  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const FabricOutcome authority = impl_->authority_check_locked(context, std::nullopt, set_id);
  if (!authority.succeeded()) {
    return authority;
  }
  if (const auto replay =
          impl_->attempt_check_locked(context, "set_member_admin_enabled", fields);
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
  detail::MemberRecord& member = record->members.at(path_entry->second);
  if (member_is_terminal(member)) {
    return make_rejection(OutcomeCode::INVALID_LIFECYCLE_TRANSITION,
                          "member " + member_id.str() + " is " +
                              std::string(to_string(member.lifecycle)) +
                              " and cannot be administratively toggled");
  }
  if (context.expected_member_generation.has_value() &&
      !(member.generation == *context.expected_member_generation)) {
    return make_rejection(OutcomeCode::STALE_MEMBER_GENERATION,
                          "expected member generation " +
                              std::to_string(context.expected_member_generation->value()) +
                              " but the member is at " +
                              std::to_string(member.generation.value()));
  }
  if (member.admin_enabled == enabled) {
    FabricOutcome outcome =
        make_outcome(OutcomeCode::IDEMPOTENT,
                     std::string("member administrative enablement already ") +
                         (enabled ? "true" : "false"));
    impl_->finalize_outcome_locked(*record, outcome);
    impl_->record_attempt_locked(context, "set_member_admin_enabled", fields, outcome);
    return outcome;
  }
  if (!member.generation.next().has_value() || !record->generation.next().has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "generation exhausted for set " + set_id.str());
  }
  member.admin_enabled = enabled;
  const auto advanced_member = member.generation.next();
  if (advanced_member.has_value()) {
    member.generation = *advanced_member;
  }
  impl_->bump_member_watermark_locked(member);
  // Re-enabling is an explicit administrative act, so the member is
  // re-evaluated as an explicit revalidation. Disabling records the
  // administrative cause immediately.
  impl_->evaluate_member_locked(*record, member, view, enabled);
  impl_->recompute_locked(*record);

  CommitSpec spec;
  spec.event = SetEvent::MEMBERSHIP_RECHECK;
  spec.cause = enabled ? MembershipCause::ADMIN_ENABLED : MembershipCause::ADMIN_DISABLED;
  spec.member_id = member_id;
  spec.path_id = member.path_id;
  spec.summary = std::string("member administrative enablement -> ") +
                 (enabled ? "true" : "false") + "; member lifecycle=" +
                 std::string(to_string(member.lifecycle)) + " currentness=" +
                 std::string(to_string(member.currentness));
  return impl_->commit_locked(*record, context, "set_member_admin_enabled", fields, spec,
                              make_outcome(OutcomeCode::UPDATED, spec.summary));
}

}  // namespace multipath_fabric
