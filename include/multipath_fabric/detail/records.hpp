// Engine record layout.
//
// INTERNAL. These structures are the mutable representation owned by
// FabricEngine. They are installed with the package because the persistence
// codec and the test suite use them directly, but they are not part of the
// stable consumption surface: consumers observe immutable SetSnapshot values.
// Mutable internals are never handed out by the public API.
#ifndef MULTIPATH_FABRIC_DETAIL_RECORDS_HPP
#define MULTIPATH_FABRIC_DETAIL_RECORDS_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/detail/bytes.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"
#include "multipath_fabric/path_authority.hpp"

namespace multipath_fabric {

// Semantic uniqueness key of a multipath set. Generation is deliberately not
// part of it, and neither is any publisher process incarnation. A set keeps its
// identity across ordinary membership mutation; mutation advances generations.
struct SetKey {
  FabricId fabric;
  MultipathNamespace name_space;
  MultipathSetName name;

  [[nodiscard]] bool valid() const noexcept {
    return fabric.valid() && name_space.valid() && name.valid();
  }
  [[nodiscard]] bool operator==(const SetKey& other) const noexcept {
    return fabric == other.fabric && name_space == other.name_space && name == other.name;
  }
  [[nodiscard]] bool operator<(const SetKey& other) const noexcept {
    if (!(fabric == other.fabric)) {
      return fabric < other.fabric;
    }
    if (!(name_space == other.name_space)) {
      return name_space < other.name_space;
    }
    return name < other.name;
  }
  [[nodiscard]] std::string render() const;
};

namespace detail {

struct MemberRecord {
  MultipathMemberId id;
  PathId path_id;
  PathAuthorityGeneration bound_authority_generation;
  MultipathMemberGeneration generation;
  MemberLifecycle lifecycle = MemberLifecycle::PENDING;
  MemberCurrentness currentness = MemberCurrentness::PENDING_EVALUATION;
  bool admin_enabled = true;
  // Monotonic watermark over every input that can make this membership usable
  // or unusable. A revalidation begun at watermark W may only commit while the
  // watermark is still W.
  Watermark invalidation_watermark;
  std::uint32_t pending_revalidations = 0;
  MembershipProvenance provenance;
  std::optional<MultipathMemberId> predecessor;
  std::optional<MultipathMemberId> successor;
  // The exact Path Authority view this member was last evaluated against. It is
  // an observation, never authority: it exists so that a change to the set's
  // declared conditional-authority policy can be re-evaluated against the same
  // observation without a fresh lookup.
  std::optional<PathAuthorityGeneration> observed_authority_generation;
  std::optional<PathAuthorityState> observed_authority_state;

  [[nodiscard]] bool usable() const noexcept {
    return member_is_usable(lifecycle, currentness);
  }
};

struct HistoryEntry {
  MultipathSetGeneration set_generation;
  SetEvent event = SetEvent::DECLARE;
  MembershipCause cause = MembershipCause::DECLARED;
  PublisherId publisher;
  CoordinatorEpoch epoch;
  std::optional<MultipathMemberId> member_id;
  std::optional<PathId> path_id;
  std::string summary;

  [[nodiscard]] std::string render() const;
};

struct SetRecord {
  MultipathSetId id;
  SetKey key;
  MultipathSetGeneration generation;
  MembershipGeneration membership_generation;
  MultipathAuthorityGeneration authority_generation;
  SetLifecycle lifecycle = SetLifecycle::DECLARED;
  SetCurrentness currentness = SetCurrentness::CURRENT;
  bool admin_enabled = true;
  std::uint64_t minimum_usable_members = 1;
  bool conditional_authority_permitted = false;
  CoordinatorEpoch governing_epoch;
  MembershipProvenance provenance;
  std::optional<MultipathSetId> superseded_by;
  std::optional<MultipathSetId> supersedes;
  std::optional<RevocationRecord> revocation;
  std::string withdrawal_reason;
  std::vector<HistoryEntry> history;
  // Bumped whenever any set-level input to member usability changes.
  Watermark invalidation_watermark;

  // Canonical membership: ordered by PathId, then by member id when two
  // distinct membership relations somehow share a path (which the duplicate
  // rule forbids in a current set, but which must still have a total order for
  // historically withdrawn relations).
  std::map<PathId, MemberRecord> members;
  // Member identity index. Every value in members has exactly one entry here.
  std::map<MultipathMemberId, PathId> member_index;

  // Derived and maintained by the engine; recomputed by the property tests.
  std::uint64_t usable_member_count = 0;

  [[nodiscard]] bool published() const noexcept {
    return lifecycle != SetLifecycle::DECLARED;
  }
  [[nodiscard]] bool terminal() const noexcept {
    return lifecycle == SetLifecycle::WITHDRAWN || lifecycle == SetLifecycle::SUPERSEDED ||
           lifecycle == SetLifecycle::REVOKED || lifecycle == SetLifecycle::RETIRED;
  }
  [[nodiscard]] std::uint64_t recompute_usable_members() const noexcept;
};

// Semantic digest of a set. Canonical byte stream, insertion-order independent.
[[nodiscard]] Digest128 compute_set_digest(const SetRecord& record);

// Digest of a single member's semantic state, used for diff identity.
[[nodiscard]] Digest128 compute_member_digest(const MemberRecord& record);

// Fingerprint of a semantic mutation request, used to decide whether an attempt
// id is an exact replay or a conflict.
[[nodiscard]] Digest128 fingerprint_request(std::string_view operation,
                                            const std::vector<std::string>& fields);

}  // namespace detail
}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_DETAIL_RECORDS_HPP
