#include "engine_impl.hpp"

#include <algorithm>
#include <vector>
#include <sstream>

namespace multipath_fabric {

bool member_is_terminal(const detail::MemberRecord& member) noexcept {
  return member.lifecycle == MemberLifecycle::WITHDRAWN ||
         member.lifecycle == MemberLifecycle::SUPERSEDED ||
         member.lifecycle == MemberLifecycle::RETIRED;
}

std::uint64_t live_member_count(const detail::SetRecord& record) noexcept {
  std::uint64_t count = 0;
  for (const auto& entry : record.members) {
    if (!member_is_terminal(entry.second)) {
      ++count;
    }
  }
  return count;
}

std::uint64_t archived_member_count(const detail::SetRecord& record) noexcept {
  std::uint64_t count = 0;
  for (const auto& entry : record.members) {
    if (member_is_terminal(entry.second)) {
      ++count;
    }
  }
  return count;
}

void FabricEngine::Impl::finalize_outcome_locked(const detail::SetRecord& record,
                                                 FabricOutcome& outcome) const {
  outcome.set_id = record.id;
  outcome.set_generation = record.generation;
  outcome.membership_generation = record.membership_generation;
  outcome.authority_generation = record.authority_generation;
  outcome.lifecycle = record.lifecycle;
  outcome.currentness = record.currentness;
  outcome.usable_members = consumable_member_count(record);
  outcome.minimum_usable_members = record.minimum_usable_members;
  outcome.digest = detail::compute_set_digest(record);
}

void FabricEngine::Impl::prune_archive_locked(detail::SetRecord& record) {
  std::vector<PathId> archived;
  for (const auto& entry : record.members) {
    if (member_is_terminal(entry.second)) {
      archived.push_back(entry.first);
    }
  }
  std::vector<MultipathMemberId> pruned;
  while (archived.size() > config.limits.max_archived_members_per_set) {
    const PathId victim = archived.front();
    archived.erase(archived.begin());
    const auto found = record.members.find(victim);
    if (found == record.members.end()) {
      continue;
    }
    pruned.push_back(found->second.id);
    record.member_index.erase(found->second.id);
    unindex_path_locked(record.id, victim);
    if (total_members > 0) {
      --total_members;
    }
    record.members.erase(found);
  }
  if (pruned.empty()) {
    return;
  }
  // Clear only the lineage references that point at relations this pass removed.
  // References to relations that were replaced in place are intentional lineage
  // and must survive pruning.
  for (auto& entry : record.members) {
    detail::MemberRecord& member = entry.second;
    if (member.predecessor.has_value() &&
        std::find(pruned.begin(), pruned.end(), *member.predecessor) != pruned.end()) {
      member.predecessor.reset();
    }
    if (member.successor.has_value() &&
        std::find(pruned.begin(), pruned.end(), *member.successor) != pruned.end()) {
      member.successor.reset();
    }
  }
}

FabricOutcome FabricEngine::Impl::commit_locked(detail::SetRecord& record,
                                                const MutationContext& context,
                                                std::string_view operation,
                                                const std::vector<std::string>& fields,
                                                const CommitSpec& spec,
                                                FabricOutcome outcome) {
  if (spec.advance_set_generation) {
    if (!advance_set_generation_locked(record)) {
      return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                            "multipath set generation is exhausted for " + record.id.str());
    }
  }
  if (spec.advance_membership_generation) {
    if (!advance_membership_generation_locked(record)) {
      return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                            "membership generation is exhausted for " + record.id.str());
    }
  }
  record.provenance = make_provenance_locked(context, spec.cause, record);
  prune_archive_locked(record);
  append_history_locked(record, spec.event, spec.cause, &context, spec.member_id, spec.path_id,
                        spec.summary);
  capture_snapshot_locked(record);
  finalize_outcome_locked(record, outcome);
  record_attempt_locked(context, operation, fields, outcome);
  return outcome;
}

std::optional<PathId> FabricEngine::Impl::member_path(const MultipathSetId& set_id,
                                                      const MultipathMemberId& member_id) const {
  std::shared_lock<std::shared_mutex> lock(mutex);
  const auto set = sets.find(set_id);
  if (set == sets.end()) {
    return std::nullopt;
  }
  const auto path = set->second.member_index.find(member_id);
  if (path == set->second.member_index.end()) {
    return std::nullopt;
  }
  return path->second;
}

std::vector<PathId> FabricEngine::Impl::live_member_paths(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(mutex);
  std::vector<PathId> paths;
  const auto set = sets.find(set_id);
  if (set == sets.end()) {
    return paths;
  }
  for (const auto& entry : set->second.members) {
    if (!member_is_terminal(entry.second)) {
      paths.push_back(entry.first);
    }
  }
  return paths;
}

}  // namespace multipath_fabric
