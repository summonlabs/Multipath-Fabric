// Configured resource limits.
//
// Every field declared here is consulted by the code path named in its comment.
// A limit that is not consulted must not exist: the test suite drives each one
// to its boundary and asserts the exact structured rejection.
#ifndef MULTIPATH_FABRIC_LIMITS_HPP
#define MULTIPATH_FABRIC_LIMITS_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace multipath_fabric {

struct Limits {
  // Consulted by: fabric create_set and by persistence restore.
  std::uint64_t max_sets = 100000;
  // Consulted by: fabric add_member, the bulk publication path, and restore.
  std::uint64_t max_members_per_set = 64;
  // Consulted by: fabric add_member, bulk publication, and restore.
  std::uint64_t max_total_members = 1000000;
  // Consulted by: bounded per-set history retention.
  std::uint64_t max_history_per_set = 64;
  // Consulted by: the bounded archive of terminal membership relations
  // (withdrawn, superseded, retired). The oldest archive entries are pruned
  // first and surviving records have their dangling lineage references cleared.
  std::uint64_t max_archived_members_per_set = 64;
  // Consulted by: the framed wire encoder and the frame decoder.
  std::uint64_t max_frame_bytes = 1U << 20;
  // Consulted by: bulk membership publication.
  std::uint64_t max_batch_size = 256;
  // Consulted by: publisher registration.
  std::uint64_t max_publishers = 64;
  // Consulted by: the coordinator session table on accept.
  std::uint64_t max_sessions = 128;
  // Consulted by: explanation construction.
  std::uint64_t max_explanation_entries = 512;
  // Consulted by: the persistence encoder (per record and for the whole store).
  std::uint64_t max_persistence_record_bytes = 16U << 20;
  std::uint64_t max_store_bytes = 64U << 20;
  // Consulted by: the bounded attempt-id table used for replay recognition.
  std::uint64_t max_attempts = 8192;
  // Consulted by: begin_member_revalidation.
  std::uint64_t max_pending_revalidations_per_set = 64;
  // Consulted by: add_member when a path is already a dependency of many sets.
  std::uint64_t max_path_dependencies_per_path = 4096;
  // Consulted by: snapshot retention.
  std::uint64_t max_snapshot_history = 16;
  // Consulted by: publisher scope registration.
  std::uint64_t max_scope_set_ids = 256;

  // Renders one "name=value" line per limit, in declaration order. The CLI
  // prints this and the tests iterate it to prove that no limit is dead.
  [[nodiscard]] std::vector<std::pair<std::string, std::uint64_t>> describe() const;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_LIMITS_HPP
