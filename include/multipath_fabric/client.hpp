// Coordinator client.
//
// One client owns one TCP connection and one server-assigned session identity.
// It is NOT thread safe: use one client per thread. The client fills the
// connection session identity into every mutation context it sends, so the
// coordinator can bind each request to the connection that issued it.
#ifndef MULTIPATH_FABRIC_CLIENT_HPP
#define MULTIPATH_FABRIC_CLIENT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "multipath_fabric/fabric.hpp"
#include "multipath_fabric/socket.hpp"
#include "multipath_fabric/wire.hpp"

namespace multipath_fabric {

struct ClientConfig {
  std::uint32_t connect_timeout_ms = 5000;
  std::uint32_t frame_total_timeout_ms = 30000;
  std::uint32_t poll_interval_ms = 50;
  std::uint32_t send_timeout_ms = 30000;
  std::uint64_t max_frame_bytes = 1U << 20;
};

class MultipathFabricClient {
 public:
  explicit MultipathFabricClient(ClientConfig config = ClientConfig{});
  ~MultipathFabricClient();

  MultipathFabricClient(const MultipathFabricClient&) = delete;
  MultipathFabricClient& operator=(const MultipathFabricClient&) = delete;
  MultipathFabricClient(MultipathFabricClient&&) = delete;
  MultipathFabricClient& operator=(MultipathFabricClient&&) = delete;

  [[nodiscard]] FabricOutcome connect(const std::string& host, std::uint16_t port);
  void close();
  [[nodiscard]] bool connected() const noexcept { return socket_.valid(); }
  [[nodiscard]] const SessionId& session() const noexcept { return session_; }
  // Governing epoch as last announced by the coordinator. The client stamps it
  // into every mutation context whose epoch is unset. A caller may set the epoch
  // explicitly in order to exercise stale-epoch rejection deliberately.
  [[nodiscard]] CoordinatorEpoch governing_epoch() const noexcept { return epoch_; }
  [[nodiscard]] const PublisherId& registered_publisher() const noexcept { return publisher_; }
  [[nodiscard]] const WorkerBootId& registered_worker_boot() const noexcept {
    return worker_boot_;
  }
  // Re-reads the governing epoch from the coordinator without changing the
  // session. Never done implicitly: carrying a superseded epoch must fail.
  [[nodiscard]] FabricOutcome refresh_epoch();
  [[nodiscard]] std::uint64_t frames_sent() const noexcept { return frames_sent_; }
  [[nodiscard]] std::uint64_t frames_received() const noexcept { return frames_received_; }

  // Raw exchange. Returns the transport result; the coordinator's verdict is
  // written into p response.outcome.
  [[nodiscard]] FabricOutcome call(const wire::WireRequest& request, wire::WireResponse& response);

  // -- operations ------------------------------------------------------------

  [[nodiscard]] FabricOutcome register_publisher(const PublisherId& publisher,
                                                 const WorkerBootId& worker_boot,
                                                 const AuthorityScope& scope);
  [[nodiscard]] FabricOutcome create_set(const MutationContext& context, const SetKey& key,
                                         const SetOptions& options);
  [[nodiscard]] FabricOutcome add_member(const MutationContext& context,
                                         const MultipathSetId& set_id, const PathId& path,
                                         const PathAuthorityGeneration& generation);
  [[nodiscard]] FabricOutcome add_members(const MutationContext& context,
                                          const MultipathSetId& set_id,
                                          const std::vector<MemberRequest>& members);
  [[nodiscard]] FabricOutcome remove_member(const MutationContext& context,
                                            const MultipathSetId& set_id,
                                            const MultipathMemberId& member_id,
                                            const std::string& reason);
  [[nodiscard]] FabricOutcome withdraw_member(const MutationContext& context,
                                              const MultipathSetId& set_id,
                                              const MultipathMemberId& member_id,
                                              const std::string& reason);
  [[nodiscard]] FabricOutcome replace_member(const MutationContext& context,
                                             const MultipathSetId& set_id,
                                             const MultipathMemberId& member_id,
                                             const PathId& successor_path,
                                             const PathAuthorityGeneration& successor_generation,
                                             const std::string& reason);
  [[nodiscard]] FabricOutcome set_member_admin_enabled(const MutationContext& context,
                                                       const MultipathSetId& set_id,
                                                       const MultipathMemberId& member_id,
                                                       bool enabled);
  [[nodiscard]] FabricOutcome set_minimum(const MutationContext& context,
                                          const MultipathSetId& set_id, std::uint64_t minimum);
  [[nodiscard]] FabricOutcome set_conditional_policy(const MutationContext& context,
                                                      const MultipathSetId& set_id,
                                                      bool permitted);
  [[nodiscard]] FabricOutcome set_admin_enabled(const MutationContext& context,
                                                const MultipathSetId& set_id, bool enabled);
  [[nodiscard]] FabricOutcome publish_set(const MutationContext& context,
                                          const MultipathSetId& set_id);
  [[nodiscard]] FabricOutcome withdraw_set(const MutationContext& context,
                                           const MultipathSetId& set_id,
                                           const std::string& reason);
  [[nodiscard]] FabricOutcome complete_withdrawal(const MutationContext& context,
                                                  const MultipathSetId& set_id);
  [[nodiscard]] FabricOutcome revoke_set(const MutationContext& context,
                                         const MultipathSetId& set_id, RevocationReason reason,
                                         const std::string& detail);
  [[nodiscard]] FabricOutcome retire_set(const MutationContext& context,
                                         const MultipathSetId& set_id,
                                         const std::string& reason);
  [[nodiscard]] FabricOutcome supersede_set(const MutationContext& context,
                                            const MultipathSetId& predecessor,
                                            const MultipathSetId& successor);
  [[nodiscard]] FabricOutcome revalidate_set(const MutationContext& context,
                                             const MultipathSetId& set_id);
  [[nodiscard]] FabricOutcome revalidate_member(const MutationContext& context,
                                                const MultipathSetId& set_id,
                                                const MultipathMemberId& member_id);
  [[nodiscard]] FabricOutcome apply_path_authority(const MutationContext& context,
                                                   const PathAuthorityView& view);
  [[nodiscard]] FabricOutcome declare_path_authority(const MutationContext& context,
                                                     const PathAuthorityView& view);
  [[nodiscard]] FabricOutcome refresh_path(const MutationContext& context, const PathId& path);
  [[nodiscard]] FabricOutcome advance_epoch(const MutationContext& context,
                                            const CoordinatorEpoch& expected_epoch);

  // -- queries ---------------------------------------------------------------

  [[nodiscard]] FabricOutcome list_sets(std::vector<MultipathSetId>& out);
  [[nodiscard]] FabricOutcome query_set(const MultipathSetId& set_id, SetSnapshot& out);
  [[nodiscard]] FabricOutcome request_snapshot(const MultipathSetId& set_id,
                                               const SnapshotId& snapshot_id, SetSnapshot& out);
  [[nodiscard]] FabricOutcome explain_set(const MultipathSetId& set_id, SetExplanation& out);

 private:
  [[nodiscard]] FabricOutcome exchange(wire::MessageId id, const wire::WireRequest& request,
                                       wire::WireResponse& response);

  [[nodiscard]] FabricOutcome read_hello_ack();
  [[nodiscard]] MutationContext stamp(MutationContext context) const;

  ClientConfig config_;
  net::Socket socket_;
  SessionId session_;
  CoordinatorEpoch epoch_;
  // Identity established by the most recent successful registration on this
  // connection. Filled into mutation contexts whose caller left them unset.
  PublisherId publisher_;
  WorkerBootId worker_boot_;
  std::uint64_t frames_sent_ = 0;
  std::uint64_t frames_received_ = 0;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_CLIENT_HPP
