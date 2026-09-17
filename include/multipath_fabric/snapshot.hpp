// Immutable set snapshots.
//
// A snapshot is a value. It is produced under the engine's lock and handed out
// by value, so it can never expose mutable engine internals and can never be
// used to mutate anything. Old snapshots remain inspectable; they carry no
// mutation authority whatsoever.
#ifndef MULTIPATH_FABRIC_SNAPSHOT_HPP
#define MULTIPATH_FABRIC_SNAPSHOT_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/detail/bytes.hpp"
#include "multipath_fabric/detail/records.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"

namespace multipath_fabric {

struct MemberSnapshot {
  MultipathMemberId id;
  PathId path_id;
  PathAuthorityGeneration bound_authority_generation;
  MultipathMemberGeneration generation;
  MemberLifecycle lifecycle = MemberLifecycle::PENDING;
  MemberCurrentness currentness = MemberCurrentness::PENDING_EVALUATION;
  bool admin_enabled = true;
  bool usable = false;
  Watermark invalidation_watermark;
  std::uint32_t pending_revalidations = 0;
  std::optional<MultipathMemberId> predecessor;
  std::optional<MultipathMemberId> successor;
  MembershipProvenance provenance;

  [[nodiscard]] std::string render() const;
};

struct SetSnapshot {
  // Content addressed: "snap-" followed by the 32 hex characters of the
  // semantic digest. Identical semantic state always yields the identical
  // snapshot identity, and the identity changes whenever the digest changes.
  SnapshotId snapshot_id;
  MultipathSetId set_id;
  SetKey key;
  MultipathSetGeneration generation;
  MembershipGeneration membership_generation;
  MultipathAuthorityGeneration authority_generation;
  SetLifecycle lifecycle = SetLifecycle::DECLARED;
  SetCurrentness currentness = SetCurrentness::CURRENT;
  RouteReadiness readiness = RouteReadiness::NOT_PUBLISHED;
  bool admin_enabled = true;
  std::uint64_t minimum_usable_members = 0;
  bool conditional_authority_permitted = false;
  std::uint64_t usable_member_count = 0;
  std::uint64_t member_count = 0;
  CoordinatorEpoch governing_epoch;
  MembershipProvenance provenance;
  std::optional<MultipathSetId> superseded_by;
  std::optional<MultipathSetId> supersedes;
  std::optional<RevocationRecord> revocation;
  std::string withdrawal_reason;
  std::vector<MemberSnapshot> members;  // canonical order: PathId, then member id
  std::vector<detail::HistoryEntry> history;
  detail::Digest128 digest;

  // Deterministic multi-line rendering. Used by the CLI, by examples and by
  // tests. Equivalent states reached in different publication order render
  // identically.
  [[nodiscard]] std::string render() const;

  [[nodiscard]] const MemberSnapshot* find_member(const PathId& path) const noexcept;
  [[nodiscard]] const MemberSnapshot* find_member(const MultipathMemberId& id) const noexcept;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_SNAPSHOT_HPP
