#include "multipath_fabric/client.hpp"

#include <atomic>

namespace multipath_fabric {

MultipathFabricClient::MultipathFabricClient(ClientConfig config) : config_(config) {}

MultipathFabricClient::~MultipathFabricClient() { close(); }

FabricOutcome MultipathFabricClient::connect(const std::string& host, std::uint16_t port) {
  close();
  net::ensure_transport_initialised();
  net::Socket socket;
  const FabricOutcome connected =
      net::tcp_connect(host, port, config_.connect_timeout_ms, socket);
  if (!connected.succeeded()) {
    return connected;
  }
  socket_ = std::move(socket);

  // The coordinator announces the connection session identity and the governing
  // epoch before the client sends anything.
  const FabricOutcome result = read_hello_ack();
  if (!result.succeeded()) {
    close();
    return result;
  }
  return make_outcome(OutcomeCode::OK, "connected with session " + session_.str() + " epoch " +
                                           std::to_string(epoch_.value()));
}

FabricOutcome MultipathFabricClient::read_hello_ack() {
  const std::atomic<bool> never_stop{false};
  std::vector<std::uint8_t> header(wire::frame_header_size);
  std::size_t received = 0;
  FabricOutcome result =
      net::socket_recv_exact(socket_, header.data(), header.size(), config_.poll_interval_ms,
                             config_.frame_total_timeout_ms, &never_stop, received);
  if (!result.succeeded()) {
    return result;
  }
  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t payload_length = 0;
  result = wire::decode_header(header.data(), header.size(), config_.max_frame_bytes, id, payload_length);
  if (!result.succeeded()) {
    return result;
  }
  if (id != wire::MessageId::HELLO_ACK) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "coordinator did not answer with HELLO_ACK");
  }
  std::vector<std::uint8_t> payload(payload_length);
  if (payload_length > 0) {
    std::size_t payload_received = 0;
    result = net::socket_recv_exact(socket_, payload.data(), payload.size(),
                                    config_.poll_interval_ms, config_.frame_total_timeout_ms,
                                    &never_stop, payload_received);
    if (!result.succeeded()) {
      return result;
    }
  }
  result = wire::verify_integrity(header.data(), header.size(), payload);
  if (!result.succeeded()) {
    return result;
  }
  ++frames_received_;
  detail::ByteReader reader(payload.data(), payload.size());
  const auto session_text = reader.string(128);
  const auto epoch_value = reader.u64();
  if (!session_text.has_value() || !epoch_value.has_value() || !reader.at_end()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "coordinator sent a malformed session announcement");
  }
  const auto session = SessionId::parse(*session_text);
  const auto epoch = CoordinatorEpoch::from_value(*epoch_value);
  if (!session.has_value() || !epoch.has_value()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "coordinator sent an invalid session identity or epoch");
  }
  session_ = *session;
  epoch_ = *epoch;
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome MultipathFabricClient::refresh_epoch() {
  if (!socket_.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "client is not connected");
  }
  std::vector<std::uint8_t> frame;
  FabricOutcome result =
      wire::encode_frame(wire::MessageId::HELLO, std::vector<std::uint8_t>{},
                         config_.max_frame_bytes, frame);
  if (!result.succeeded()) {
    return result;
  }
  const std::atomic<bool> never_stop{false};
  result = net::socket_send_all(socket_, frame.data(), frame.size(), config_.send_timeout_ms,
                                &never_stop);
  if (!result.succeeded()) {
    close();
    return result;
  }
  ++frames_sent_;
  return read_hello_ack();
}

MutationContext MultipathFabricClient::stamp(MutationContext context) const {
  context.session = session_;
  if (!context.epoch.valid()) {
    context.epoch = epoch_;
  }
  if (!context.publisher.valid()) {
    context.publisher = publisher_;
  }
  if (!context.worker_boot.valid()) {
    context.worker_boot = worker_boot_;
  }
  return context;
}

void MultipathFabricClient::close() {
  if (socket_.valid()) {
    socket_.close();
  }
  session_ = SessionId{};
}

FabricOutcome MultipathFabricClient::exchange(wire::MessageId id, const wire::WireRequest& request,
                                              wire::WireResponse& response) {
  if (!socket_.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "client is not connected");
  }
  std::vector<std::uint8_t> payload;
  FabricOutcome result = wire::encode_request(request, payload);
  if (!result.succeeded()) {
    return result;
  }
  std::vector<std::uint8_t> frame;
  result = wire::encode_frame(id, payload, config_.max_frame_bytes, frame);
  if (!result.succeeded()) {
    return result;
  }
  const std::atomic<bool> never_stop{false};
  result = net::socket_send_all(socket_, frame.data(), frame.size(), config_.send_timeout_ms,
                                &never_stop);
  if (!result.succeeded()) {
    close();
    return result;
  }
  ++frames_sent_;

  std::vector<std::uint8_t> header(wire::frame_header_size);
  std::size_t received = 0;
  result = net::socket_recv_exact(socket_, header.data(), header.size(), config_.poll_interval_ms,
                                  config_.frame_total_timeout_ms, &never_stop, received);
  if (!result.succeeded()) {
    close();
    return result;
  }
  wire::MessageId response_id = wire::MessageId::RESULT;
  std::uint32_t payload_length = 0;
  result = wire::decode_header(header.data(), header.size(), config_.max_frame_bytes,
                               response_id, payload_length);
  if (!result.succeeded()) {
    close();
    return result;
  }
  std::vector<std::uint8_t> response_payload(payload_length);
  if (payload_length > 0) {
    std::size_t payload_received = 0;
    result = net::socket_recv_exact(socket_, response_payload.data(), response_payload.size(),
                                    config_.poll_interval_ms, config_.frame_total_timeout_ms,
                                    &never_stop, payload_received);
    if (!result.succeeded()) {
      close();
      return result;
    }
  }
  result = wire::verify_integrity(header.data(), header.size(), response_payload);
  if (!result.succeeded()) {
    close();
    return result;
  }
  ++frames_received_;
  detail::ByteReader reader(response_payload.data(), response_payload.size());
  wire::WireResponse decoded;
  result = wire::decode_response(reader, decoded);
  if (!result.succeeded() || !reader.at_end()) {
    close();
    return result.succeeded()
               ? make_rejection(OutcomeCode::FRAMING_ERROR,
                                "response payload has trailing bytes after the declared fields")
               : result;
  }
  response = std::move(decoded);
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome MultipathFabricClient::call(const wire::WireRequest& request,
                                          wire::WireResponse& response) {
  return exchange(request.id, request, response);
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

FabricOutcome MultipathFabricClient::register_publisher(const PublisherId& publisher,
                                                        const WorkerBootId& worker_boot,
                                                        const AuthorityScope& scope) {
  wire::WireRequest request;
  request.id = wire::MessageId::REGISTER_PUBLISHER;
  request.context.publisher = publisher;
  request.context.worker_boot = worker_boot;
  request.context.session = session_;
  request.scope = scope;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  if (!transport.succeeded()) {
    return transport;
  }
  if (response.outcome.succeeded()) {
    publisher_ = publisher;
    worker_boot_ = worker_boot;
  }
  return response.outcome;
}

FabricOutcome MultipathFabricClient::create_set(const MutationContext& context, const SetKey& key,
                                                const SetOptions& options) {
  wire::WireRequest request;
  request.id = wire::MessageId::CREATE_SET;
  request.context = stamp(context);
  request.key = key;
  request.options = options;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::add_member(const MutationContext& context,
                                                const MultipathSetId& set_id, const PathId& path,
                                                const PathAuthorityGeneration& generation) {
  wire::WireRequest request;
  request.id = wire::MessageId::ADD_MEMBER;
  request.context = stamp(context);
  request.set_id = set_id;
  request.path_id = path;
  request.path_authority_generation = generation;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::add_members(const MutationContext& context,
                                                 const MultipathSetId& set_id,
                                                 const std::vector<MemberRequest>& members) {
  wire::WireRequest request;
  request.id = wire::MessageId::ADD_MEMBERS;
  request.context = stamp(context);
  request.set_id = set_id;
  request.members = members;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::remove_member(const MutationContext& context,
                                                   const MultipathSetId& set_id,
                                                   const MultipathMemberId& member_id,
                                                   const std::string& reason) {
  wire::WireRequest request;
  request.id = wire::MessageId::REMOVE_MEMBER;
  request.context = stamp(context);
  request.set_id = set_id;
  request.member_id = member_id;
  request.text = reason;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::withdraw_member(const MutationContext& context,
                                                     const MultipathSetId& set_id,
                                                     const MultipathMemberId& member_id,
                                                     const std::string& reason) {
  wire::WireRequest request;
  request.id = wire::MessageId::WITHDRAW_MEMBER;
  request.context = stamp(context);
  request.set_id = set_id;
  request.member_id = member_id;
  request.text = reason;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::replace_member(
    const MutationContext& context, const MultipathSetId& set_id,
    const MultipathMemberId& member_id, const PathId& successor_path,
    const PathAuthorityGeneration& successor_generation, const std::string& reason) {
  wire::WireRequest request;
  request.id = wire::MessageId::REPLACE_MEMBER;
  request.context = stamp(context);
  request.set_id = set_id;
  request.member_id = member_id;
  request.path_id = successor_path;
  request.path_authority_generation = successor_generation;
  request.text = reason;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::set_member_admin_enabled(const MutationContext& context,
                                                              const MultipathSetId& set_id,
                                                              const MultipathMemberId& member_id,
                                                              bool enabled) {
  wire::WireRequest request;
  request.id = enabled ? wire::MessageId::MEMBER_ADMIN_ENABLE
                       : wire::MessageId::MEMBER_ADMIN_DISABLE;
  request.context = stamp(context);
  request.set_id = set_id;
  request.member_id = member_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::set_minimum(const MutationContext& context,
                                                 const MultipathSetId& set_id,
                                                 std::uint64_t minimum) {
  wire::WireRequest request;
  request.id = wire::MessageId::SET_MINIMUM;
  request.context = stamp(context);
  request.set_id = set_id;
  request.number = minimum;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::set_conditional_policy(const MutationContext& context,
                                                            const MultipathSetId& set_id,
                                                            bool permitted) {
  wire::WireRequest request;
  request.id = wire::MessageId::SET_CONDITIONAL_POLICY;
  request.context = stamp(context);
  request.set_id = set_id;
  request.flag = permitted;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::set_admin_enabled(const MutationContext& context,
                                                       const MultipathSetId& set_id,
                                                       bool enabled) {
  wire::WireRequest request;
  request.id = enabled ? wire::MessageId::SET_ADMIN_ENABLE : wire::MessageId::SET_ADMIN_DISABLE;
  request.context = stamp(context);
  request.set_id = set_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::publish_set(const MutationContext& context,
                                                 const MultipathSetId& set_id) {
  wire::WireRequest request;
  request.id = wire::MessageId::ADVANCE_SET_STATE;
  request.context = stamp(context);
  request.set_id = set_id;
  request.state_action = wire::SetStateAction::PUBLISH;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::withdraw_set(const MutationContext& context,
                                                  const MultipathSetId& set_id,
                                                  const std::string& reason) {
  wire::WireRequest request;
  request.id = wire::MessageId::ADVANCE_SET_STATE;
  request.context = stamp(context);
  request.set_id = set_id;
  request.state_action = wire::SetStateAction::WITHDRAW;
  request.text = reason;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::complete_withdrawal(const MutationContext& context,
                                                         const MultipathSetId& set_id) {
  wire::WireRequest request;
  request.id = wire::MessageId::ADVANCE_SET_STATE;
  request.context = stamp(context);
  request.set_id = set_id;
  request.state_action = wire::SetStateAction::COMPLETE_WITHDRAWAL;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::revoke_set(const MutationContext& context,
                                                const MultipathSetId& set_id,
                                                RevocationReason reason,
                                                const std::string& detail) {
  wire::WireRequest request;
  request.id = wire::MessageId::REVOKE_SET;
  request.context = stamp(context);
  request.set_id = set_id;
  request.revocation_reason = reason;
  request.text = detail;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::retire_set(const MutationContext& context,
                                                const MultipathSetId& set_id,
                                                const std::string& reason) {
  wire::WireRequest request;
  request.id = wire::MessageId::RETIRE_SET;
  request.context = stamp(context);
  request.set_id = set_id;
  request.text = reason;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::supersede_set(const MutationContext& context,
                                                   const MultipathSetId& predecessor,
                                                   const MultipathSetId& successor) {
  wire::WireRequest request;
  request.id = wire::MessageId::SUPERSEDE_SET;
  request.context = stamp(context);
  request.set_id = predecessor;
  request.text = successor.str();
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::revalidate_set(const MutationContext& context,
                                                    const MultipathSetId& set_id) {
  wire::WireRequest request;
  request.id = wire::MessageId::REVALIDATE_SET;
  request.context = stamp(context);
  request.set_id = set_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::revalidate_member(const MutationContext& context,
                                                       const MultipathSetId& set_id,
                                                       const MultipathMemberId& member_id) {
  wire::WireRequest request;
  request.id = wire::MessageId::REVALIDATE_MEMBER;
  request.context = stamp(context);
  request.set_id = set_id;
  request.member_id = member_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::apply_path_authority(const MutationContext& context,
                                                          const PathAuthorityView& view) {
  wire::WireRequest request;
  request.id = wire::MessageId::APPLY_PATH_AUTHORITY;
  request.context = stamp(context);
  request.path_id = view.path;
  request.path_authority_generation = view.generation;
  request.path_state = view.state;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::declare_path_authority(const MutationContext& context,
                                                               const PathAuthorityView& view) {
  wire::WireRequest request;
  request.id = wire::MessageId::DECLARE_PATH_AUTHORITY;
  request.context = stamp(context);
  request.path_id = view.path;
  request.path_authority_generation = view.generation;
  request.path_state = view.state;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::refresh_path(const MutationContext& context,
                                                  const PathId& path) {
  wire::WireRequest request;
  request.id = wire::MessageId::REFRESH_PATH;
  request.context = stamp(context);
  request.path_id = path;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::advance_epoch(const MutationContext& context,
                                                   const CoordinatorEpoch& expected_epoch) {
  wire::WireRequest request;
  request.id = wire::MessageId::EPOCH_ADVANCE;
  request.context = stamp(context);
  request.number = expected_epoch.value();
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  return transport.succeeded() ? response.outcome : transport;
}

FabricOutcome MultipathFabricClient::list_sets(std::vector<MultipathSetId>& out) {
  wire::WireRequest request;
  request.id = wire::MessageId::LIST_SETS;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  if (!transport.succeeded()) {
    return transport;
  }
  if (response.outcome.succeeded()) {
    out = response.set_ids;
  }
  return response.outcome;
}

FabricOutcome MultipathFabricClient::query_set(const MultipathSetId& set_id, SetSnapshot& out) {
  wire::WireRequest request;
  request.id = wire::MessageId::QUERY_SET;
  request.set_id = set_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  if (!transport.succeeded()) {
    return transport;
  }
  if (response.outcome.succeeded() && response.snapshot.has_value()) {
    out = *response.snapshot;
  }
  return response.outcome;
}

FabricOutcome MultipathFabricClient::request_snapshot(const MultipathSetId& set_id,
                                                      const SnapshotId& snapshot_id,
                                                      SetSnapshot& out) {
  wire::WireRequest request;
  request.id = wire::MessageId::SNAPSHOT_REQUEST;
  request.set_id = set_id;
  request.snapshot_id = snapshot_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  if (!transport.succeeded()) {
    return transport;
  }
  if (response.outcome.succeeded() && response.snapshot.has_value()) {
    out = *response.snapshot;
  }
  return response.outcome;
}

FabricOutcome MultipathFabricClient::explain_set(const MultipathSetId& set_id,
                                                 SetExplanation& out) {
  wire::WireRequest request;
  request.id = wire::MessageId::EXPLAIN_SET;
  request.set_id = set_id;
  wire::WireResponse response;
  const FabricOutcome transport = call(request, response);
  if (!transport.succeeded()) {
    return transport;
  }
  if (response.outcome.succeeded() && response.explanation.has_value()) {
    out = *response.explanation;
  }
  return response.outcome;
}

}  // namespace multipath_fabric