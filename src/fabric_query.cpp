#include "engine_impl.hpp"

#include <algorithm>
#include <map>
#include <sstream>

namespace multipath_fabric {

// ---------------------------------------------------------------------------
// Snapshot construction
// ---------------------------------------------------------------------------

SnapshotId FabricEngine::Impl::snapshot_id_for(const detail::Digest128& digest) {
  return SnapshotId::require("snap-" + digest.to_hex());
}

std::optional<MemberSnapshot> FabricEngine::Impl::make_member_snapshot_locked(
    const detail::MemberRecord& member) const {
  MemberSnapshot snapshot;
  snapshot.id = member.id;
  snapshot.path_id = member.path_id;
  snapshot.bound_authority_generation = member.bound_authority_generation;
  snapshot.generation = member.generation;
  snapshot.lifecycle = member.lifecycle;
  snapshot.currentness = member.currentness;
  snapshot.admin_enabled = member.admin_enabled;
  snapshot.usable = member_inputs_usable(member);
  snapshot.invalidation_watermark = member.invalidation_watermark;
  snapshot.pending_revalidations = member.pending_revalidations;
  snapshot.predecessor = member.predecessor;
  snapshot.successor = member.successor;
  snapshot.provenance = member.provenance;
  return snapshot;
}

SetSnapshot FabricEngine::Impl::make_snapshot_locked(const detail::SetRecord& record) const {
  SetSnapshot snapshot;
  snapshot.set_id = record.id;
  snapshot.key = record.key;
  snapshot.generation = record.generation;
  snapshot.membership_generation = record.membership_generation;
  snapshot.authority_generation = record.authority_generation;
  snapshot.lifecycle = record.lifecycle;
  snapshot.currentness = record.currentness;
  snapshot.readiness = route_readiness(record.lifecycle, record.currentness);
  snapshot.admin_enabled = record.admin_enabled;
  snapshot.minimum_usable_members = record.minimum_usable_members;
  snapshot.conditional_authority_permitted = record.conditional_authority_permitted;
  snapshot.usable_member_count = record.usable_member_count;
  snapshot.member_count = record.members.size();
  snapshot.governing_epoch = record.governing_epoch;
  snapshot.provenance = record.provenance;
  snapshot.superseded_by = record.superseded_by;
  snapshot.supersedes = record.supersedes;
  snapshot.revocation = record.revocation;
  snapshot.withdrawal_reason = record.withdrawal_reason;
  snapshot.history = record.history;
  snapshot.members.reserve(record.members.size());
  // record.members is ordered by PathId, which is the canonical member order.
  for (const auto& entry : record.members) {
    const auto member = make_member_snapshot_locked(entry.second);
    if (member.has_value()) {
      snapshot.members.push_back(*member);
    }
  }
  snapshot.digest = detail::compute_set_digest(record);
  snapshot.snapshot_id = snapshot_id_for(snapshot.digest);
  return snapshot;
}

void FabricEngine::Impl::capture_snapshot_locked(detail::SetRecord& record) {
  SetSnapshot snapshot = make_snapshot_locked(record);
  auto& history = snapshot_history[record.id];
  if (!history.empty() && history.back().snapshot_id == snapshot.snapshot_id) {
    return;
  }
  history.push_back(std::move(snapshot));
  while (history.size() > config.limits.max_snapshot_history) {
    history.pop_front();
  }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

std::size_t FabricEngine::set_count() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->sets.size();
}

std::size_t FabricEngine::total_member_count() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  return impl_->total_members;
}

std::vector<MultipathSetId> FabricEngine::list_sets() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  std::vector<MultipathSetId> ids;
  ids.reserve(impl_->sets.size());
  for (const auto& entry : impl_->sets) {
    ids.push_back(entry.first);
  }
  return ids;
}

std::vector<MultipathSetId> FabricEngine::sets_for_path(const PathId& path) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  std::vector<MultipathSetId> ids;
  const auto found = impl_->path_dependents.find(path);
  if (found == impl_->path_dependents.end()) {
    return ids;
  }
  ids.assign(found->second.begin(), found->second.end());
  return ids;
}

std::optional<MultipathSetId> FabricEngine::find_set_by_key(const SetKey& key) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->key_index.find(key);
  if (found == impl_->key_index.end()) {
    return std::nullopt;
  }
  return found->second;
}

std::optional<SetSnapshot> FabricEngine::snapshot(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->sets.find(set_id);
  if (found == impl_->sets.end()) {
    return std::nullopt;
  }
  return impl_->make_snapshot_locked(found->second);
}

std::optional<SetSnapshot> FabricEngine::snapshot_by_key(const SetKey& key) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto id = impl_->key_index.find(key);
  if (id == impl_->key_index.end()) {
    return std::nullopt;
  }
  const auto found = impl_->sets.find(id->second);
  if (found == impl_->sets.end()) {
    return std::nullopt;
  }
  return impl_->make_snapshot_locked(found->second);
}

std::optional<RouteReadiness> FabricEngine::readiness(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->sets.find(set_id);
  if (found == impl_->sets.end()) {
    return std::nullopt;
  }
  return route_readiness(found->second.lifecycle, found->second.currentness);
}

std::vector<SnapshotId> FabricEngine::snapshot_history(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  std::vector<SnapshotId> ids;
  const auto found = impl_->snapshot_history.find(set_id);
  if (found == impl_->snapshot_history.end()) {
    return ids;
  }
  ids.reserve(found->second.size());
  for (const auto& snapshot : found->second) {
    ids.push_back(snapshot.snapshot_id);
  }
  return ids;
}

std::optional<SetSnapshot> FabricEngine::historical_snapshot(const MultipathSetId& set_id,
                                                             const SnapshotId& snapshot_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->snapshot_history.find(set_id);
  if (found == impl_->snapshot_history.end()) {
    return std::nullopt;
  }
  for (const auto& snapshot : found->second) {
    if (snapshot.snapshot_id == snapshot_id) {
      return snapshot;
    }
  }
  return std::nullopt;
}

std::optional<SnapshotDiff> FabricEngine::diff_snapshots(const MultipathSetId& set_id,
                                                         const SnapshotId& before,
                                                         const SnapshotId& after) const {
  const auto before_snapshot = historical_snapshot(set_id, before);
  const auto after_snapshot = historical_snapshot(set_id, after);
  if (!before_snapshot.has_value() || !after_snapshot.has_value()) {
    return std::nullopt;
  }
  return multipath_fabric::diff_snapshots(*before_snapshot, *after_snapshot);
}

std::optional<SnapshotDiff> FabricEngine::diff_last_two(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->snapshot_history.find(set_id);
  if (found == impl_->snapshot_history.end() || found->second.size() < 2) {
    return std::nullopt;
  }
  const SetSnapshot& after = found->second[found->second.size() - 1];
  const SetSnapshot& before = found->second[found->second.size() - 2];
  return multipath_fabric::diff_snapshots(before, after);
}

std::vector<detail::HistoryEntry> FabricEngine::history(const MultipathSetId& set_id) const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->sets.find(set_id);
  if (found == impl_->sets.end()) {
    return {};
  }
  return found->second.history;
}

std::vector<detail::Digest128> FabricEngine::set_digests() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  std::vector<detail::Digest128> digests;
  digests.reserve(impl_->sets.size());
  for (const auto& entry : impl_->sets) {
    digests.push_back(detail::compute_set_digest(entry.second));
  }
  return digests;
}

// ---------------------------------------------------------------------------
// Explanations
// ---------------------------------------------------------------------------

std::optional<SetExplanation> FabricEngine::explain_set(const MultipathSetId& set_id) const {
  const std::vector<PathId> paths = impl_->live_member_paths(set_id);
  std::map<PathId, std::optional<PathAuthorityView>> observed;
  for (const auto& path : paths) {
    observed.emplace(path, impl_->lookup_path(path));
  }
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  const auto found = impl_->sets.find(set_id);
  if (found == impl_->sets.end()) {
    return std::nullopt;
  }
  return impl_->make_explanation_locked(found->second, observed);
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

FabricIntegrityReport FabricEngine::check_integrity() const {
  std::shared_lock<std::shared_mutex> lock(impl_->mutex);
  FabricIntegrityReport report;
  report.set_count = impl_->sets.size();
  report.path_index_entries = impl_->path_dependents.size();
  report.key_index_entries = impl_->key_index.size();
  report.registration_count = impl_->registrations.size();
  report.fence_count = impl_->fences.size();
  report.retained_attempts = impl_->attempts.size();

  std::size_t counted_members = 0;
  for (const auto& entry : impl_->sets) {
    const detail::SetRecord& record = entry.second;
    report.usable_member_count += record.usable_member_count;
    counted_members += record.members.size();
    if (record.recompute_usable_members() != record.usable_member_count) {
      report.problems.push_back("set " + record.id.str() +
                                ": usable_member_count is stale (" +
                                std::to_string(record.usable_member_count) + " recorded, " +
                                std::to_string(record.recompute_usable_members()) + " actual)");
    }
    if (record.members.size() != record.member_index.size()) {
      report.problems.push_back("set " + record.id.str() +
                                ": member table and member index have different sizes");
    }
    if (record.minimum_usable_members > impl_->config.limits.max_members_per_set) {
      report.problems.push_back("set " + record.id.str() +
                                ": minimum_usable_members exceeds max_members_per_set");
    }
    if (!record.published() && record.lifecycle != SetLifecycle::DECLARED) {
      report.problems.push_back("set " + record.id.str() + ": impossible lifecycle/publication "
                                                          "combination");
    }
    if (record.lifecycle == SetLifecycle::RETIRED && record.currentness == SetCurrentness::CURRENT) {
      report.problems.push_back("set " + record.id.str() +
                                ": a retired set must not report live currentness");
    }
    const auto key_entry = impl_->key_index.find(record.key);
    if (key_entry == impl_->key_index.end() || !(key_entry->second == record.id)) {
      report.problems.push_back("set " + record.id.str() + ": semantic key index does not resolve "
                                                          "to this set");
    }
    for (const auto& member : record.members) {
      if (!(member.second.path_id == member.first)) {
        report.problems.push_back("set " + record.id.str() + ": member " +
                                  member.second.id.str() +
                                  " is stored under a different path key");
      }
      const auto index_entry = record.member_index.find(member.second.id);
      if (index_entry == record.member_index.end() || !(index_entry->second == member.first)) {
        report.problems.push_back("set " + record.id.str() + ": member identity index does not "
                                                          "resolve for " +
                                  member.second.id.str());
      }
      const auto dependents = impl_->path_dependents.find(member.first);
      if (dependents == impl_->path_dependents.end() ||
          dependents->second.find(record.id) == dependents->second.end()) {
        report.problems.push_back("path index is missing set " + record.id.str() + " for path " +
                                  member.first.str());
      }
    }
  }
  report.member_count = counted_members;
  if (counted_members != impl_->total_members) {
    report.problems.push_back("total_members counter is " +
                              std::to_string(impl_->total_members) + " but " +
                              std::to_string(counted_members) + " member records exist");
  }
  for (const auto& entry : impl_->path_dependents) {
    for (const auto& set_id : entry.second) {
      const auto record = impl_->sets.find(set_id);
      if (record == impl_->sets.end()) {
        report.problems.push_back("path index references unknown set " + set_id.str());
        continue;
      }
      if (record->second.members.find(entry.first) == record->second.members.end()) {
        report.problems.push_back("path index lists path " + entry.first.str() + " for set " +
                                  set_id.str() + " which has no such member");
      }
    }
  }
  for (const auto& entry : impl_->attempt_index) {
    bool found = false;
    for (const auto& record : impl_->attempts) {
      if (record.attempt == entry.first) {
        found = true;
        break;
      }
    }
    if (!found) {
      report.problems.push_back("attempt index references an evicted attempt record");
    }
  }
  report.consistent = report.problems.empty();
  return report;
}

std::string FabricIntegrityReport::render() const {
  std::ostringstream stream;
  stream << (consistent ? "CONSISTENT" : "INCONSISTENT") << " sets=" << set_count
         << " members=" << member_count << " usable=" << usable_member_count
         << " path_index=" << path_index_entries << " key_index=" << key_index_entries
         << " registrations=" << registration_count << " fences=" << fence_count
         << " attempts=" << retained_attempts;
  for (const auto& problem : problems) {
    stream << "\n  problem: " << problem;
  }
  return stream.str();
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string MemberSnapshot::render() const {
  std::ostringstream stream;
  stream << "member " << id.view() << " path=" << path_id.view()
         << " authority_generation=" << bound_authority_generation.value()
         << " member_generation=" << generation.value() << " lifecycle=" << to_string(lifecycle)
         << " currentness=" << to_string(currentness) << " usable=" << (usable ? "true" : "false")
         << " admin_enabled=" << (admin_enabled ? "true" : "false")
         << " watermark=" << invalidation_watermark.value()
         << " pending_revalidations=" << pending_revalidations;
  if (predecessor.has_value()) {
    stream << " predecessor=" << predecessor->view();
  }
  if (successor.has_value()) {
    stream << " successor=" << successor->view();
  }
  stream << " | " << provenance.render();
  return stream.str();
}

std::string SetSnapshot::render() const {
  std::ostringstream stream;
  stream << "set " << set_id.view() << " key=" << key.render()
         << "\n  generation=" << generation.value()
         << " membership_generation=" << membership_generation.value()
         << " authority_generation=" << authority_generation.value()
         << " governing_epoch=" << governing_epoch.value()
         << "\n  lifecycle=" << to_string(lifecycle) << " currentness=" << to_string(currentness)
         << " readiness=" << to_string(readiness)
         << "\n  members=" << member_count << " usable=" << usable_member_count
         << " minimum_usable_members=" << minimum_usable_members
         << " admin_enabled=" << (admin_enabled ? "true" : "false")
         << " conditional_authority_permitted="
         << (conditional_authority_permitted ? "true" : "false")
         << "\n  snapshot=" << snapshot_id.view() << " digest=" << digest.to_hex();
  if (superseded_by.has_value()) {
    stream << "\n  superseded_by=" << superseded_by->view();
  }
  if (supersedes.has_value()) {
    stream << "\n  supersedes=" << supersedes->view();
  }
  if (revocation.has_value()) {
    stream << "\n  revocation=" << revocation->render();
  }
  if (!withdrawal_reason.empty()) {
    stream << "\n  withdrawal_reason=\"" << withdrawal_reason << "\"";
  }
  stream << "\n  provenance: " << provenance.render();
  for (const auto& member : members) {
    stream << "\n  " << member.render();
  }
  return stream.str();
}

const MemberSnapshot* SetSnapshot::find_member(const PathId& path) const noexcept {
  for (const auto& member : members) {
    if (member.path_id == path) {
      return &member;
    }
  }
  return nullptr;
}

const MemberSnapshot* SetSnapshot::find_member(const MultipathMemberId& id) const noexcept {
  for (const auto& member : members) {
    if (member.id == id) {
      return &member;
    }
  }
  return nullptr;
}

std::string StoreStatistics::render() const {
  std::ostringstream stream;
  stream << "store format=" << format_version << " sets=" << set_count
         << " members=" << member_count << " revocations=" << revocation_count
         << " fences=" << fence_count << " epoch=" << epoch.value()
         << " authority_generation=" << authority_generation.value()
         << " payload_digest=" << payload_digest.to_hex()
         << " recovered_from_backup=" << (recovered_from_backup ? "true" : "false");
  return stream.str();
}

}  // namespace multipath_fabric
