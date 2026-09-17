// FabricEngine: the Multipath Fabric governance runtime.
//
// THREAD SAFETY
// -------------
// Every public method is safe to call concurrently. Queries, snapshots and
// persistence reads take a shared lock; mutations take an exclusive lock.
// Internal helpers assume the lock is already held and are never called from
// outside a locked public method. No user callback and no Path Authority lookup
// is ever invoked while the engine lock is held.
//
// AUTHORITY
// ---------
// Every mutation carries a MutationContext binding the coordinator epoch, the
// publisher, the worker boot incarnation, the session, the mutation attempt id
// and the expected generations. Mutations that fail any authority check change
// nothing. See outcome.hpp for the fixed rejection precedence.
//
// CURRENTNESS
// -----------
// Usable members satisfy: member lifecycle CURRENT, member currentness CURRENT,
// owning set published and not administratively disabled. Path Authority
// generation currency is checked before the legality state, so a historical
// AUTHORIZED result never counts after its generation changed.
//
// RECOVERY
// --------
// Loading a store restores durable membership description only. Live authority
// is never restored from disk: the epoch advances, every set becomes
// currentness REVALIDATION_REQUIRED, and every previously registered publisher
// must register again with a fresh worker boot.
#ifndef MULTIPATH_FABRIC_FABRIC_HPP
#define MULTIPATH_FABRIC_FABRIC_HPP

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/detail/records.hpp"
#include "multipath_fabric/diff.hpp"
#include "multipath_fabric/explanation.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/limits.hpp"
#include "multipath_fabric/outcome.hpp"
#include "multipath_fabric/path_authority.hpp"
#include "multipath_fabric/snapshot.hpp"

namespace multipath_fabric {

struct FabricConfig {
  Limits limits;
  CoordinatorEpoch initial_epoch = CoordinatorEpoch::first();
  MultipathAuthorityGeneration initial_authority_generation =
      MultipathAuthorityGeneration::first();
};

struct SetOptions {
  std::uint64_t minimum_usable_members = 1;
  bool admin_enabled = true;
  bool conditional_authority_permitted = false;
};

struct MemberRequest {
  PathId path_id;
  PathAuthorityGeneration authority_generation;
};

struct RevalidationTicket {
  MultipathSetId set_id;
  MultipathMemberId member_id;
  RevalidationAttemptId attempt;
  MultipathMemberGeneration member_generation;
  Watermark set_watermark;
  Watermark member_watermark;
  CoordinatorEpoch epoch;
  PathAuthorityGeneration bound_authority_generation;
  bool valid = false;
};

struct RevalidationBegin {
  FabricOutcome outcome;
  std::optional<RevalidationTicket> ticket;
};

struct FabricIntegrityReport {
  bool consistent = true;
  std::vector<std::string> problems;
  std::size_t set_count = 0;
  std::size_t member_count = 0;
  std::size_t usable_member_count = 0;
  std::size_t path_index_entries = 0;
  std::size_t key_index_entries = 0;
  std::size_t registration_count = 0;
  std::size_t fence_count = 0;
  std::size_t retained_attempts = 0;

  [[nodiscard]] std::string render() const;
};

struct StoreStatistics {
  std::uint32_t format_version = 0;
  std::size_t set_count = 0;
  std::size_t member_count = 0;
  std::size_t revocation_count = 0;
  std::size_t fence_count = 0;
  CoordinatorEpoch epoch;
  MultipathAuthorityGeneration authority_generation;
  detail::Digest128 payload_digest;
  // True when the primary store file was unusable and the previous-generation
  // backup was loaded instead.
  bool recovered_from_backup = false;

  [[nodiscard]] std::string render() const;
};

class FabricEngine {
 public:
  explicit FabricEngine(FabricConfig config = FabricConfig{});
  ~FabricEngine();

  FabricEngine(const FabricEngine&) = delete;
  FabricEngine& operator=(const FabricEngine&) = delete;
  FabricEngine(FabricEngine&&) = delete;
  FabricEngine& operator=(FabricEngine&&) = delete;

  // -- Path Authority binding ------------------------------------------------

  // Installs the Path Authority consumption surface. By default the engine
  // consumes a coordinator-owned reference directory that is fed through
  // declare_path_authority(). Installing an external source replaces it, which
  // is how a deployment wires the real Path Authority runtime in. The source is
  // called outside the engine lock and is never mutated by Multipath Fabric.
  void bind_path_authority(std::shared_ptr<const PathAuthoritySource> source);
  [[nodiscard]] bool has_path_authority() const;
  // Records the exact Path Authority view the coordinator consumes for a path
  // and immediately applies it to every dependent set. This is the coordinator
  // side of a Path Authority bridge; it is authority checked like any mutation.
  // Rejected with UNSUPPORTED_OPERATION when an external source is installed,
  // because then the external runtime owns the view.
  [[nodiscard]] FabricOutcome declare_path_authority(const MutationContext& context,
                                                     const PathAuthorityView& view);

  // -- authority -------------------------------------------------------------

  [[nodiscard]] CoordinatorEpoch epoch() const;
  [[nodiscard]] MultipathAuthorityGeneration authority_generation() const;
  [[nodiscard]] Limits limits() const;

  FabricOutcome register_publisher(const PublisherId& publisher, const WorkerBootId& worker_boot,
                                   const AuthorityScope& scope, const SessionId& session);
  FabricOutcome unregister_publisher(const PublisherId& publisher,
                                     const WorkerBootId& worker_boot);
  FabricOutcome fence_worker(const PublisherId& publisher, const WorkerBootId& worker_boot,
                             std::string cause);
  FabricOutcome advance_epoch(const PublisherId& publisher, const WorkerBootId& worker_boot,
                              const SessionId& session, const CoordinatorEpoch& expected_epoch,
                              const MutationAttemptId& attempt);
  [[nodiscard]] bool is_fenced(const PublisherId& publisher,
                               const WorkerBootId& worker_boot) const;
  [[nodiscard]] std::optional<PublisherRegistration> find_registration(
      const PublisherId& publisher, const WorkerBootId& worker_boot) const;
  [[nodiscard]] AuthorityDescription describe_authority() const;

  // -- set lifecycle ---------------------------------------------------------

  FabricOutcome create_set(const MutationContext& context, const SetKey& key,
                           const SetOptions& options);
  FabricOutcome publish_set(const MutationContext& context, const MultipathSetId& set_id);
  FabricOutcome set_minimum_usable_members(const MutationContext& context,
                                           const MultipathSetId& set_id,
                                           std::uint64_t minimum_usable_members);
  FabricOutcome set_conditional_authority_policy(const MutationContext& context,
                                                 const MultipathSetId& set_id,
                                                 bool permitted);
  FabricOutcome set_admin_enabled(const MutationContext& context, const MultipathSetId& set_id,
                                  bool enabled);
  FabricOutcome withdraw_set(const MutationContext& context, const MultipathSetId& set_id,
                             std::string reason);
  FabricOutcome complete_withdrawal(const MutationContext& context,
                                   const MultipathSetId& set_id);
  FabricOutcome revoke_set(const MutationContext& context, const MultipathSetId& set_id,
                           RevocationReason reason, std::string detail);
  FabricOutcome retire_set(const MutationContext& context, const MultipathSetId& set_id,
                           std::string reason);
  FabricOutcome supersede_set(const MutationContext& context, const MultipathSetId& predecessor,
                              const MultipathSetId& successor);

  // -- membership ------------------------------------------------------------

  FabricOutcome add_member(const MutationContext& context, const MultipathSetId& set_id,
                           const PathId& path_id,
                           const PathAuthorityGeneration& authority_generation);
  // Bulk publication is an all-or-nothing semantic transaction: either every
  // accepted member is committed and the set generation advances once, or
  // nothing changes and the first rejection is returned.
  FabricOutcome add_members(const MutationContext& context, const MultipathSetId& set_id,
                            const std::vector<MemberRequest>& requests);
  FabricOutcome remove_member(const MutationContext& context, const MultipathSetId& set_id,
                              const MultipathMemberId& member_id, std::string reason);
  FabricOutcome withdraw_member(const MutationContext& context, const MultipathSetId& set_id,
                                const MultipathMemberId& member_id, std::string reason);
  FabricOutcome replace_member(const MutationContext& context, const MultipathSetId& set_id,
                               const MultipathMemberId& member_id, const PathId& successor_path,
                               const PathAuthorityGeneration& successor_generation,
                               std::string reason);
  FabricOutcome set_member_admin_enabled(const MutationContext& context,
                                         const MultipathSetId& set_id,
                                         const MultipathMemberId& member_id, bool enabled);

  // -- revalidation ----------------------------------------------------------

  FabricOutcome revalidate_set(const MutationContext& context, const MultipathSetId& set_id);
  FabricOutcome revalidate_member(const MutationContext& context, const MultipathSetId& set_id,
                                  const MultipathMemberId& member_id);
  // Two-phase revalidation. begin_member_revalidation captures the member's
  // invalidation watermark; complete_member_revalidation refuses to commit when
  // any input changed in between. This is the mechanism that stops a stale
  // asynchronous completion from resurrecting a member whose Path Authority
  // generation was superseded while revalidation was in flight.
  RevalidationBegin begin_member_revalidation(const MutationContext& context,
                                              const MultipathSetId& set_id,
                                              const MultipathMemberId& member_id,
                                              const RevalidationAttemptId& attempt);
  FabricOutcome complete_member_revalidation(const MutationContext& context,
                                             const RevalidationTicket& ticket,
                                             const std::optional<PathAuthorityView>& current);
  FabricOutcome abandon_member_revalidation(const RevalidationTicket& ticket);

  // -- dependency invalidation ----------------------------------------------

  // Applies an externally observed Path Authority view to every set that
  // depends on the exact path. Only dependent sets are touched. The caller's
  // scope must cover every dependent set.
  FabricOutcome apply_path_authority(const MutationContext& context,
                                     const PathAuthorityView& view);
  // Looks the path up in the bound Path Authority source and applies the
  // result. Returns PATH_AUTHORITY_UNKNOWN when no source is bound or the
  // source has no record of the path.
  FabricOutcome refresh_path(const MutationContext& context, const PathId& path);

  // -- queries ---------------------------------------------------------------

  [[nodiscard]] std::size_t set_count() const;
  [[nodiscard]] std::size_t total_member_count() const;
  [[nodiscard]] std::vector<MultipathSetId> list_sets() const;
  [[nodiscard]] std::vector<MultipathSetId> sets_for_path(const PathId& path) const;
  [[nodiscard]] std::optional<MultipathSetId> find_set_by_key(const SetKey& key) const;
  [[nodiscard]] std::optional<SetSnapshot> snapshot(const MultipathSetId& set_id) const;
  [[nodiscard]] std::optional<SetSnapshot> snapshot_by_key(const SetKey& key) const;
  [[nodiscard]] std::optional<RouteReadiness> readiness(const MultipathSetId& set_id) const;
  [[nodiscard]] std::vector<SnapshotId> snapshot_history(const MultipathSetId& set_id) const;
  [[nodiscard]] std::optional<SetSnapshot> historical_snapshot(const MultipathSetId& set_id,
                                                               const SnapshotId& snapshot_id) const;
  [[nodiscard]] std::optional<SnapshotDiff> diff_snapshots(const MultipathSetId& set_id,
                                                           const SnapshotId& before,
                                                           const SnapshotId& after) const;
  [[nodiscard]] std::optional<SnapshotDiff> diff_last_two(const MultipathSetId& set_id) const;
  [[nodiscard]] std::optional<SetExplanation> explain_set(const MultipathSetId& set_id) const;
  [[nodiscard]] std::vector<detail::HistoryEntry> history(const MultipathSetId& set_id) const;
  [[nodiscard]] FabricIntegrityReport check_integrity() const;
  [[nodiscard]] std::vector<detail::Digest128> set_digests() const;

  // -- persistence -----------------------------------------------------------

  FabricOutcome save_store(const std::string& path) const;
  FabricOutcome load_store(const std::string& path);
  static FabricOutcome inspect_store_file(const std::string& path, StoreStatistics& statistics);

 private:
  // Shared implementation of single and bulk membership publication. Both use
  // exactly the same validation sequence; bulk additionally applies every
  // accepted member in one all-or-nothing commit.
  FabricOutcome add_members_internal(const MutationContext& context,
                                     const MultipathSetId& set_id,
                                     const std::vector<MemberRequest>& requests,
                                     std::string_view operation, bool bulk);

  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_FABRIC_HPP
