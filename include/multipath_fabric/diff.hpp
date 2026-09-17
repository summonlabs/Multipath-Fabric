// Deterministic snapshot diffs.
#ifndef MULTIPATH_FABRIC_DIFF_HPP
#define MULTIPATH_FABRIC_DIFF_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "multipath_fabric/detail/records.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/snapshot.hpp"

namespace multipath_fabric {

enum class DiffKind : std::uint8_t {
  SET_GENERATION_CHANGED = 1,
  MEMBERSHIP_GENERATION_CHANGED = 2,
  AUTHORITY_GENERATION_CHANGED = 3,
  SET_LIFECYCLE_CHANGED = 4,
  SET_CURRENTNESS_CHANGED = 5,
  READINESS_CHANGED = 6,
  SET_ADMIN_CHANGED = 7,
  MINIMUM_CHANGED = 8,
  CONDITIONAL_POLICY_CHANGED = 9,
  GOVERNING_EPOCH_CHANGED = 10,
  USABLE_COUNT_CHANGED = 11,
  SUPERSEDED_BY_CHANGED = 12,
  REVOCATION_CHANGED = 13,
  WITHDRAWAL_REASON_CHANGED = 14,
  MEMBER_ADDED = 15,
  MEMBER_REMOVED = 16,
  MEMBER_PATH_AUTHORITY_GENERATION_CHANGED = 17,
  MEMBER_LIFECYCLE_CHANGED = 18,
  MEMBER_CURRENTNESS_CHANGED = 19,
  MEMBER_ADMIN_CHANGED = 20,
  MEMBER_GENERATION_CHANGED = 21,
  MEMBER_PENDING_REVALIDATIONS_CHANGED = 22,
};

[[nodiscard]] std::string_view to_string(DiffKind kind) noexcept;
[[nodiscard]] bool valid_diff_kind(std::uint8_t raw) noexcept;

struct DiffEntry {
  DiffKind kind = DiffKind::SET_GENERATION_CHANGED;
  // The subject of the change: a member id, a path id, or "-" for set-level
  // facts.
  std::string subject;
  std::string before;
  std::string after;

  [[nodiscard]] std::string render() const;

  // Stable ordering key: (kind, subject, before, after).
  [[nodiscard]] bool operator<(const DiffEntry& other) const noexcept;
  [[nodiscard]] bool operator==(const DiffEntry& other) const noexcept;
};

struct SnapshotDiff {
  MultipathSetId set_id;
  SnapshotId before_snapshot;
  SnapshotId after_snapshot;
  MultipathSetGeneration before_generation;
  MultipathSetGeneration after_generation;
  detail::Digest128 before_digest;
  detail::Digest128 after_digest;
  bool identical = true;
  std::vector<DiffEntry> entries;  // stable order

  [[nodiscard]] std::string render() const;
};

// Computes the deterministic diff between two snapshots of the same set.
// Returns nullopt when the snapshots do not describe the same set identity.
[[nodiscard]] std::optional<SnapshotDiff> diff_snapshots(const SetSnapshot& before,
                                                         const SetSnapshot& after);

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_DIFF_HPP
