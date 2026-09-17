// Internal engine state and locked helpers.
//
// INTERNAL HEADER. Not installed. Every helper documented as "_locked" must be
// called with Impl::mutex held, either shared (read-only helpers) or exclusive
// (mutating helpers). No helper calls user code, takes another lock, performs
// IO or emits callbacks.
#ifndef MULTIPATH_FABRIC_SRC_ENGINE_IMPL_HPP
#define MULTIPATH_FABRIC_SRC_ENGINE_IMPL_HPP

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <utility>
#include <vector>

#include "multipath_fabric/fabric.hpp"

namespace multipath_fabric {

struct AttemptRecord {
  MutationAttemptId attempt;
  detail::Digest128 fingerprint;
  FabricOutcome outcome;
};

// Does the member's own inputs currently make it usable, irrespective of the
// owning set's currentness and administrative state?
[[nodiscard]] bool member_inputs_usable(const detail::MemberRecord& member) noexcept;

// Is the set consumable right now: published, not administratively disabled,
// currently authoritative, and at or above its minimum requirement?
[[nodiscard]] bool set_is_consumable(const detail::SetRecord& record) noexcept;

// Members that actually count right now. Zero unless the set is consumable.
[[nodiscard]] std::uint64_t consumable_member_count(const detail::SetRecord& record) noexcept;

// A Path Authority input failure is recoverable when an explicit revalidation
// can clear it without any membership change.
[[nodiscard]] bool currentness_is_revalidation_recoverable(MemberCurrentness value) noexcept;

// A membership relation is terminal once it can never become usable again
// without a new membership relation.
[[nodiscard]] bool member_is_terminal(const detail::MemberRecord& member) noexcept;

// Membership relations that can still count toward a threshold.
[[nodiscard]] std::uint64_t live_member_count(const detail::SetRecord& record) noexcept;
[[nodiscard]] std::uint64_t archived_member_count(const detail::SetRecord& record) noexcept;

// Description of one accepted commit. The caller is responsible for having
// already validated authority, generation, dependency and semantic stages.
struct CommitSpec {
  bool advance_set_generation = true;
  bool advance_membership_generation = false;
  SetEvent event = SetEvent::MEMBERSHIP_RECHECK;
  MembershipCause cause = MembershipCause::MEMBER_ADDED;
  std::optional<MultipathMemberId> member_id;
  std::optional<PathId> path_id;
  std::string summary;
};

class FabricEngine::Impl {
 public:
  explicit Impl(FabricConfig config_value);

  mutable std::shared_mutex mutex;
  FabricConfig config;
  CoordinatorEpoch current_epoch;
  MultipathAuthorityGeneration current_authority_generation;

  std::map<MultipathSetId, detail::SetRecord> sets;
  std::map<SetKey, MultipathSetId> key_index;
  std::map<PathId, std::set<MultipathSetId>> path_dependents;
  std::map<std::pair<PublisherId, WorkerBootId>, PublisherRegistration> registrations;
  std::map<std::pair<PublisherId, WorkerBootId>, FenceRecord> fences;

  // Bounded attempt-id table used for replay recognition, in insertion order.
  std::deque<AttemptRecord> attempts;
  std::map<MutationAttemptId, detail::Digest128> attempt_index;

  std::map<MultipathSetId, std::deque<SetSnapshot>> snapshot_history;

  // Reference consumption directory owned by the coordinator. Members are
  // admitted against the views recorded here; an external Path Authority
  // source replaces it through FabricEngine::bind_path_authority.
  std::shared_ptr<PathAuthorityDirectory> directory;
  std::shared_ptr<const PathAuthoritySource> path_authority;
  IdFactory ids;
  std::size_t total_members = 0;

  // -- authority (lock held) -------------------------------------------------

  // Stages 2-5 of the fixed rejection precedence: caller identity, epoch,
  // worker authority and scope. Returns OK when the caller may proceed.
  [[nodiscard]] FabricOutcome authority_check_locked(
      const MutationContext& context, const std::optional<SetKey>& key,
      const std::optional<MultipathSetId>& set_id) const;

  // Stage 6. Returns a FabricOutcome when the attempt is already known.
  [[nodiscard]] std::optional<FabricOutcome> attempt_check_locked(
      const MutationContext& context, std::string_view operation,
      const std::vector<std::string>& fields) const;

  void record_attempt_locked(const MutationContext& context, std::string_view operation,
                             const std::vector<std::string>& fields,
                             const FabricOutcome& outcome);

  // -- lookup (lock held) ----------------------------------------------------

  [[nodiscard]] FabricOutcome require_set_locked(const MultipathSetId& set_id,
                                                 detail::SetRecord*& out);
  [[nodiscard]] static FabricOutcome lifecycle_rejection(SetLifecycle lifecycle,
                                                         const MultipathSetId& set_id);
  [[nodiscard]] static FabricOutcome currentness_rejection(MemberCurrentness currentness,
                                                           const PathId& path);

  // Applies a set event through the transition table. Returns the rejection
  // code when the state/event pair is illegal, otherwise nullopt.
  [[nodiscard]] std::optional<OutcomeCode> apply_transition_locked(detail::SetRecord& record,
                                                                  SetEvent event);

  // -- generation and watermark management (lock held) -----------------------

  [[nodiscard]] bool advance_set_generation_locked(detail::SetRecord& record);
  [[nodiscard]] bool advance_membership_generation_locked(detail::SetRecord& record);
  [[nodiscard]] bool advance_member_generation_locked(detail::MemberRecord& member);

  // Bumps the set watermark only. Used when one member's inputs changed.
  void bump_set_watermark_only_locked(detail::SetRecord& record);
  // Bumps the set watermark and every member watermark. Used when a set-wide
  // event (epoch advance, recovery, withdrawal, retirement) invalidates every
  // in-flight revalidation in the set.
  void bump_set_watermark_locked(detail::SetRecord& record);
  void bump_member_watermark_locked(detail::MemberRecord& member);

  // -- derived state (lock held) --------------------------------------------

  void recompute_locked(detail::SetRecord& record);
  void reassign_effective_currentness_locked(detail::SetRecord& record);
  void append_history_locked(detail::SetRecord& record, SetEvent event,
                             MembershipCause cause, const MutationContext* context,
                             std::optional<MultipathMemberId> member_id,
                             std::optional<PathId> path_id, std::string summary);
  void capture_snapshot_locked(detail::SetRecord& record);
  void prune_archive_locked(detail::SetRecord& record);

  // Completes an accepted mutation: advances the pre-validated generations,
  // refreshes provenance, appends bounded history, captures a snapshot, records
  // the attempt and fills the resulting state into the outcome.
  [[nodiscard]] FabricOutcome commit_locked(detail::SetRecord& record,
                                            const MutationContext& context,
                                            std::string_view operation,
                                            const std::vector<std::string>& fields,
                                            const CommitSpec& spec, FabricOutcome outcome);

  void finalize_outcome_locked(const detail::SetRecord& record, FabricOutcome& outcome) const;

  // Reads a member's exact path under a shared lock so the Path Authority
  // lookup can happen outside the lock.
  [[nodiscard]] std::optional<PathId> member_path(const MultipathSetId& set_id,
                                                  const MultipathMemberId& member_id) const;
  // Reads every live member path of a set under a shared lock.
  [[nodiscard]] std::vector<PathId> live_member_paths(const MultipathSetId& set_id) const;
  [[nodiscard]] SetSnapshot make_snapshot_locked(const detail::SetRecord& record) const;
  [[nodiscard]] static SnapshotId snapshot_id_for(const detail::Digest128& digest);
  [[nodiscard]] SetExplanation make_explanation_locked(
      const detail::SetRecord& record,
      const std::map<PathId, std::optional<PathAuthorityView>>& observed) const;
  [[nodiscard]] std::optional<MemberSnapshot> make_member_snapshot_locked(
      const detail::MemberRecord& member) const;

  [[nodiscard]] MembershipProvenance make_provenance_locked(const MutationContext& context,
                                                            MembershipCause cause,
                                                            const detail::SetRecord& record) const;

  // -- path indexes (lock held) ---------------------------------------------

  void index_path_locked(const MultipathSetId& set_id, const PathId& path);
  void unindex_path_locked(const MultipathSetId& set_id, const PathId& path);

  // -- dependency application (lock held) -----------------------------------

  // Re-evaluates one member against an observed Path Authority view (nullopt
  // means Path Authority has no record) and updates lifecycle, currentness and
  // the invalidation watermark.
  void evaluate_member_locked(detail::SetRecord& record, detail::MemberRecord& member,
                              const std::optional<PathAuthorityView>& view,
                              bool explicit_revalidation);

  // Rebuilds a Path Authority view from the member's last observation, if any.
  [[nodiscard]] static std::optional<PathAuthorityView> observation_of(
      const detail::MemberRecord& member);

  // Re-evaluates every live member against its own last observation. Used when a
  // set-level policy that participates in classification changes.
  void reevaluate_members_from_observations_locked(detail::SetRecord& record);

  // Applies a Path Authority view to every member bound to that exact path in
  // every dependent set. Returns the number of sets changed.
  std::size_t apply_view_locked(const PathId& path,
                                const std::optional<PathAuthorityView>& view,
                                const MutationContext* context, MembershipCause cause);

  // Post-commit reconciliation: re-reads Path Authority outside the lock and
  // applies the result when it differs from the view used for the commit.
  void reconcile_path(const PathId& path, const std::optional<PathAuthorityView>& used);

  [[nodiscard]] std::optional<PathAuthorityView> lookup_path(const PathId& path) const;

  // -- attempt table ---------------------------------------------------------

  void trim_attempts_locked();

  // -- lifecycle events for whole-set transitions ---------------------------

  // Applies the member-side consequence of a set lifecycle transition.
  void apply_member_consequences_locked(detail::SetRecord& record, SetLifecycle from,
                                        SetLifecycle to, const MutationContext* context);
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_SRC_ENGINE_IMPL_HPP
