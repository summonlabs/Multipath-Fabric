#include "multipath_fabric/limits.hpp"

namespace multipath_fabric {

std::vector<std::pair<std::string, std::uint64_t>> Limits::describe() const {
  return {
      {"max_sets", max_sets},
      {"max_members_per_set", max_members_per_set},
      {"max_total_members", max_total_members},
      {"max_history_per_set", max_history_per_set},
      {"max_archived_members_per_set", max_archived_members_per_set},
      {"max_frame_bytes", max_frame_bytes},
      {"max_batch_size", max_batch_size},
      {"max_publishers", max_publishers},
      {"max_sessions", max_sessions},
      {"max_explanation_entries", max_explanation_entries},
      {"max_persistence_record_bytes", max_persistence_record_bytes},
      {"max_store_bytes", max_store_bytes},
      {"max_attempts", max_attempts},
      {"max_pending_revalidations_per_set", max_pending_revalidations_per_set},
      {"max_path_dependencies_per_path", max_path_dependencies_per_path},
      {"max_snapshot_history", max_snapshot_history},
      {"max_scope_set_ids", max_scope_set_ids},
  };
}

}  // namespace multipath_fabric
