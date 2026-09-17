#include "multipath_fabric/diff.hpp"

#include <algorithm>
#include <map>
#include <sstream>

namespace multipath_fabric {
namespace {

void add_entry(std::vector<DiffEntry>& entries, DiffKind kind, std::string subject,
               std::string before, std::string after) {
  if (before == after) {
    return;
  }
  DiffEntry entry;
  entry.kind = kind;
  entry.subject = std::move(subject);
  entry.before = std::move(before);
  entry.after = std::move(after);
  entries.push_back(std::move(entry));
}

[[nodiscard]] std::string bool_text(bool value) { return value ? "true" : "false"; }

}  // namespace

std::string_view to_string(DiffKind kind) noexcept {
  switch (kind) {
    case DiffKind::SET_GENERATION_CHANGED: return "SET_GENERATION_CHANGED";
    case DiffKind::MEMBERSHIP_GENERATION_CHANGED: return "MEMBERSHIP_GENERATION_CHANGED";
    case DiffKind::AUTHORITY_GENERATION_CHANGED: return "AUTHORITY_GENERATION_CHANGED";
    case DiffKind::SET_LIFECYCLE_CHANGED: return "SET_LIFECYCLE_CHANGED";
    case DiffKind::SET_CURRENTNESS_CHANGED: return "SET_CURRENTNESS_CHANGED";
    case DiffKind::READINESS_CHANGED: return "READINESS_CHANGED";
    case DiffKind::SET_ADMIN_CHANGED: return "SET_ADMIN_CHANGED";
    case DiffKind::MINIMUM_CHANGED: return "MINIMUM_CHANGED";
    case DiffKind::CONDITIONAL_POLICY_CHANGED: return "CONDITIONAL_POLICY_CHANGED";
    case DiffKind::GOVERNING_EPOCH_CHANGED: return "GOVERNING_EPOCH_CHANGED";
    case DiffKind::USABLE_COUNT_CHANGED: return "USABLE_COUNT_CHANGED";
    case DiffKind::SUPERSEDED_BY_CHANGED: return "SUPERSEDED_BY_CHANGED";
    case DiffKind::REVOCATION_CHANGED: return "REVOCATION_CHANGED";
    case DiffKind::WITHDRAWAL_REASON_CHANGED: return "WITHDRAWAL_REASON_CHANGED";
    case DiffKind::MEMBER_ADDED: return "MEMBER_ADDED";
    case DiffKind::MEMBER_REMOVED: return "MEMBER_REMOVED";
    case DiffKind::MEMBER_PATH_AUTHORITY_GENERATION_CHANGED:
      return "MEMBER_PATH_AUTHORITY_GENERATION_CHANGED";
    case DiffKind::MEMBER_LIFECYCLE_CHANGED: return "MEMBER_LIFECYCLE_CHANGED";
    case DiffKind::MEMBER_CURRENTNESS_CHANGED: return "MEMBER_CURRENTNESS_CHANGED";
    case DiffKind::MEMBER_ADMIN_CHANGED: return "MEMBER_ADMIN_CHANGED";
    case DiffKind::MEMBER_GENERATION_CHANGED: return "MEMBER_GENERATION_CHANGED";
    case DiffKind::MEMBER_PENDING_REVALIDATIONS_CHANGED:
      return "MEMBER_PENDING_REVALIDATIONS_CHANGED";
  }
  return "<invalid-diff-kind>";
}

bool valid_diff_kind(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 22; }

bool DiffEntry::operator<(const DiffEntry& other) const noexcept {
  if (kind != other.kind) {
    return static_cast<std::uint8_t>(kind) < static_cast<std::uint8_t>(other.kind);
  }
  if (subject != other.subject) {
    return subject < other.subject;
  }
  if (before != other.before) {
    return before < other.before;
  }
  return after < other.after;
}

bool DiffEntry::operator==(const DiffEntry& other) const noexcept {
  return kind == other.kind && subject == other.subject && before == other.before &&
         after == other.after;
}

std::string DiffEntry::render() const {
  std::ostringstream stream;
  stream << to_string(kind) << " subject=" << subject << " before=\"" << before
         << "\" after=\"" << after << "\"";
  return stream.str();
}

std::optional<SnapshotDiff> diff_snapshots(const SetSnapshot& before, const SetSnapshot& after) {
  if (!(before.set_id == after.set_id)) {
    return std::nullopt;
  }
  SnapshotDiff diff;
  diff.set_id = before.set_id;
  diff.before_snapshot = before.snapshot_id;
  diff.after_snapshot = after.snapshot_id;
  diff.before_generation = before.generation;
  diff.after_generation = after.generation;
  diff.before_digest = before.digest;
  diff.after_digest = after.digest;

  std::vector<DiffEntry>& entries = diff.entries;
  const std::string set_subject = "-";
  add_entry(entries, DiffKind::SET_GENERATION_CHANGED, set_subject,
            std::to_string(before.generation.value()), std::to_string(after.generation.value()));
  add_entry(entries, DiffKind::MEMBERSHIP_GENERATION_CHANGED, set_subject,
            std::to_string(before.membership_generation.value()),
            std::to_string(after.membership_generation.value()));
  add_entry(entries, DiffKind::AUTHORITY_GENERATION_CHANGED, set_subject,
            std::to_string(before.authority_generation.value()),
            std::to_string(after.authority_generation.value()));
  add_entry(entries, DiffKind::SET_LIFECYCLE_CHANGED, set_subject,
            std::string(to_string(before.lifecycle)), std::string(to_string(after.lifecycle)));
  add_entry(entries, DiffKind::SET_CURRENTNESS_CHANGED, set_subject,
            std::string(to_string(before.currentness)), std::string(to_string(after.currentness)));
  add_entry(entries, DiffKind::READINESS_CHANGED, set_subject,
            std::string(to_string(before.readiness)), std::string(to_string(after.readiness)));
  add_entry(entries, DiffKind::SET_ADMIN_CHANGED, set_subject, bool_text(before.admin_enabled),
            bool_text(after.admin_enabled));
  add_entry(entries, DiffKind::MINIMUM_CHANGED, set_subject,
            std::to_string(before.minimum_usable_members),
            std::to_string(after.minimum_usable_members));
  add_entry(entries, DiffKind::CONDITIONAL_POLICY_CHANGED, set_subject,
            bool_text(before.conditional_authority_permitted),
            bool_text(after.conditional_authority_permitted));
  add_entry(entries, DiffKind::GOVERNING_EPOCH_CHANGED, set_subject,
            std::to_string(before.governing_epoch.value()),
            std::to_string(after.governing_epoch.value()));
  add_entry(entries, DiffKind::USABLE_COUNT_CHANGED, set_subject,
            std::to_string(before.usable_member_count),
            std::to_string(after.usable_member_count));
  add_entry(entries, DiffKind::SUPERSEDED_BY_CHANGED, set_subject,
            before.superseded_by.has_value() ? before.superseded_by->str() : std::string("-"),
            after.superseded_by.has_value() ? after.superseded_by->str() : std::string("-"));
  add_entry(entries, DiffKind::REVOCATION_CHANGED, set_subject,
            before.revocation.has_value() ? before.revocation->render() : std::string("-"),
            after.revocation.has_value() ? after.revocation->render() : std::string("-"));
  add_entry(entries, DiffKind::WITHDRAWAL_REASON_CHANGED, set_subject, before.withdrawal_reason,
            after.withdrawal_reason);

  // Membership comparison walks both canonical orders deterministically.
  std::map<PathId, const MemberSnapshot*> before_members;
  std::map<PathId, const MemberSnapshot*> after_members;
  for (const auto& member : before.members) {
    before_members[member.path_id] = &member;
  }
  for (const auto& member : after.members) {
    after_members[member.path_id] = &member;
  }
  std::vector<PathId> all_paths;
  all_paths.reserve(before_members.size() + after_members.size());
  for (const auto& entry : before_members) {
    all_paths.push_back(entry.first);
  }
  for (const auto& entry : after_members) {
    if (before_members.find(entry.first) == before_members.end()) {
      all_paths.push_back(entry.first);
    }
  }
  std::sort(all_paths.begin(), all_paths.end());
  all_paths.erase(std::unique(all_paths.begin(), all_paths.end()), all_paths.end());

  for (const auto& path : all_paths) {
    const auto before_entry = before_members.find(path);
    const auto after_entry = after_members.find(path);
    const bool had = before_entry != before_members.end();
    const bool has = after_entry != after_members.end();
    if (had && !has) {
      add_entry(entries, DiffKind::MEMBER_REMOVED, path.str(),
                before_entry->second->id.str(), "-");
      continue;
    }
    if (!had && has) {
      add_entry(entries, DiffKind::MEMBER_ADDED, path.str(), "-",
                after_entry->second->id.str());
      continue;
    }
    const MemberSnapshot& left = *before_entry->second;
    const MemberSnapshot& right = *after_entry->second;
    if (!(left.id == right.id)) {
      add_entry(entries, DiffKind::MEMBER_REMOVED, path.str(), left.id.str(), "-");
      add_entry(entries, DiffKind::MEMBER_ADDED, path.str(), "-", right.id.str());
    }
    add_entry(entries, DiffKind::MEMBER_PATH_AUTHORITY_GENERATION_CHANGED, path.str(),
              std::to_string(left.bound_authority_generation.value()),
              std::to_string(right.bound_authority_generation.value()));
    add_entry(entries, DiffKind::MEMBER_LIFECYCLE_CHANGED, path.str(),
              std::string(to_string(left.lifecycle)), std::string(to_string(right.lifecycle)));
    add_entry(entries, DiffKind::MEMBER_CURRENTNESS_CHANGED, path.str(),
              std::string(to_string(left.currentness)),
              std::string(to_string(right.currentness)));
    add_entry(entries, DiffKind::MEMBER_ADMIN_CHANGED, path.str(), bool_text(left.admin_enabled),
              bool_text(right.admin_enabled));
    add_entry(entries, DiffKind::MEMBER_GENERATION_CHANGED, path.str(),
              std::to_string(left.generation.value()), std::to_string(right.generation.value()));
    add_entry(entries, DiffKind::MEMBER_PENDING_REVALIDATIONS_CHANGED, path.str(),
              std::to_string(left.pending_revalidations),
              std::to_string(right.pending_revalidations));
  }

  std::stable_sort(entries.begin(), entries.end());
  diff.identical = entries.empty();
  return diff;
}

std::string SnapshotDiff::render() const {
  std::ostringstream stream;
  stream << "diff set=" << set_id.view() << " before=" << before_snapshot.view()
         << " after=" << after_snapshot.view() << " generation " << before_generation.value()
         << " -> " << after_generation.value() << " entries=" << entries.size();
  if (identical) {
    stream << " (identical)";
  }
  for (const auto& entry : entries) {
    stream << "\n  " << entry.render();
  }
  return stream.str();
}

}  // namespace multipath_fabric
