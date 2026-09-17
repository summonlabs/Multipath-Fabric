#include "multipath_fabric/server.hpp"

#include <algorithm>
#include <sstream>

namespace multipath_fabric {
namespace {

// Read-only messages carry no mutation context and are not bound to a session.
[[nodiscard]] bool requires_session(wire::MessageId id) noexcept {
  switch (id) {
    case wire::MessageId::LIST_SETS:
    case wire::MessageId::QUERY_SET:
    case wire::MessageId::EXPLAIN_SET:
    case wire::MessageId::SNAPSHOT_REQUEST:
    case wire::MessageId::SHUTDOWN:
    case wire::MessageId::HELLO:
    case wire::MessageId::HELLO_ACK:
    case wire::MessageId::SNAPSHOT_RESPONSE:
    case wire::MessageId::FENCE_NOTICE:
    case wire::MessageId::RESULT:
    case wire::MessageId::ERROR:
      return false;
    default:
      return true;
  }
}

}  // namespace

MultipathFabricServer::MultipathFabricServer(FabricEngine& engine, ServerConfig config)
    : engine_(engine), config_(std::move(config)) {}

MultipathFabricServer::~MultipathFabricServer() { stop(); }

FabricOutcome MultipathFabricServer::start() {
  if (running_.load()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "server is already running");
  }
  net::ensure_transport_initialised();
  net::Socket listener;
  std::uint16_t bound_port = 0;
  const FabricOutcome bound =
      net::tcp_listen(config_.bind_host, config_.port, listener, bound_port);
  if (!bound.succeeded()) {
    return bound;
  }
  listener_ = std::move(listener);
  port_ = bound_port;
  stopping_.store(false);
  running_.store(true);
  accept_thread_ = std::thread([this]() { accept_loop(); });
  std::ostringstream detail;
  detail << "listening on " << config_.bind_host << ':' << port_;
  return make_outcome(OutcomeCode::OK, detail.str());
}

void MultipathFabricServer::stop() {
  if (!running_.exchange(false)) {
    return;
  }
  stopping_.store(true);
  listener_.interrupt();
  listener_.close();
  if (accept_thread_.joinable()) {
    accept_thread_.join();
  }
  std::vector<std::shared_ptr<Session>> pending;
  {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto& entry : sessions_) {
      pending.push_back(entry.second);
    }
  }
  for (const auto& session : pending) {
    if (session->socket) {
      session->socket->interrupt();
      session->socket->close();
    }
  }
  for (const auto& session : pending) {
    if (session->thread.joinable()) {
      session->thread.join();
    }
  }
  {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    sessions_.clear();
  }
}

std::size_t MultipathFabricServer::active_sessions() const {
  std::lock_guard<std::mutex> guard(sessions_mutex_);
  std::size_t count = 0;
  for (const auto& entry : sessions_) {
    if (!entry.second->done.load()) {
      ++count;
    }
  }
  return count;
}

ServerStatistics MultipathFabricServer::statistics() const {
  std::lock_guard<std::mutex> guard(statistics_mutex_);
  return statistics_;
}

void MultipathFabricServer::reap_finished_sessions(bool join_all) {
  std::vector<std::shared_ptr<Session>> finished;
  {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    for (auto it = sessions_.begin(); it != sessions_.end();) {
      if (join_all || it->second->done.load()) {
        finished.push_back(it->second);
        it = sessions_.erase(it);
      } else {
        ++it;
      }
    }
  }
  for (const auto& session : finished) {
    if (session->thread.joinable()) {
      session->thread.join();
    }
  }
}

void MultipathFabricServer::accept_loop() {
  while (!stopping_.load()) {
    reap_finished_sessions(false);
    bool readable = false;
    const FabricOutcome waited =
        net::socket_wait_readable(listener_, config_.poll_interval_ms, &stopping_, readable);
    if (!waited.succeeded()) {
      if (waited.code == OutcomeCode::PROTOCOL_ERROR) {
        break;
      }
      continue;
    }
    if (!readable) {
      continue;
    }
    {
      std::lock_guard<std::mutex> guard(sessions_mutex_);
      if (sessions_.size() >= config_.limits.max_sessions) {
        std::lock_guard<std::mutex> statistics_guard(statistics_mutex_);
        ++statistics_.sessions_rejected;
        continue;
      }
    }
    net::Socket accepted;
    if (!net::tcp_accept(listener_, accepted).succeeded()) {
      continue;
    }
    auto session = std::make_shared<Session>();
    session->id = sessions_ids_.next_session_id();
    session->socket = std::make_shared<net::Socket>(std::move(accepted));
    session->socket->set_nodelay(true);
    {
      std::lock_guard<std::mutex> guard(sessions_mutex_);
      if (sessions_.size() >= config_.limits.max_sessions) {
        std::lock_guard<std::mutex> statistics_guard(statistics_mutex_);
        ++statistics_.sessions_rejected;
        session->socket->close();
        continue;
      }
      sessions_[session->id] = session;
      std::lock_guard<std::mutex> statistics_guard(statistics_mutex_);
      ++statistics_.sessions_accepted;
    }
    session->thread = std::thread([this, session]() {
      session_loop(session);
      end_session(session, "SESSION_LOST");
    });
  }
  reap_finished_sessions(true);
}

void MultipathFabricServer::end_session(const std::shared_ptr<Session>& session,
                                        const std::string& cause) {
  bool registered = false;
  PublisherId publisher;
  WorkerBootId boot;
  {
    std::lock_guard<std::mutex> guard(sessions_mutex_);
    registered = session->has_registration;
    publisher = session->publisher;
    boot = session->worker_boot;
  }
  if (registered) {
    // Real worker death becomes a permanent fence: the boot can never mutate
    // again and live currentness of sets it last mutated must be re-established.
    engine_.fence_worker(publisher, boot, cause);
    std::lock_guard<std::mutex> guard(statistics_mutex_);
    ++statistics_.workers_fenced;
  }
  if (session->socket) {
    session->socket->close();
  }
  session->done.store(true);
}

FabricOutcome MultipathFabricServer::send_hello_ack(const std::shared_ptr<Session>& session) {
  detail::ByteWriter writer(64);
  writer.string(session->id.view(), 128);
  writer.u64(engine_.epoch().value());
  std::vector<std::uint8_t> payload = writer.take();
  std::vector<std::uint8_t> frame;
  const FabricOutcome encoded = wire::encode_frame(
      wire::MessageId::HELLO_ACK, payload, config_.limits.max_frame_bytes, frame);
  if (!encoded.succeeded()) {
    return encoded;
  }
  return net::socket_send_all(*session->socket, frame.data(), frame.size(),
                              config_.send_timeout_ms, &stopping_);
}

FabricOutcome MultipathFabricServer::send_frame(const std::shared_ptr<Session>& session,
                                                wire::MessageId id,
                                                const wire::WireResponse& response) {
  std::vector<std::uint8_t> payload;
  FabricOutcome result = wire::encode_response(response, payload);
  if (!result.succeeded()) {
    return result;
  }
  std::vector<std::uint8_t> frame;
  result = wire::encode_frame(id, payload, config_.limits.max_frame_bytes, frame);
  if (!result.succeeded()) {
    return result;
  }
  return net::socket_send_all(*session->socket, frame.data(), frame.size(),
                              config_.send_timeout_ms, &stopping_);
}

FabricOutcome MultipathFabricServer::dispatch(const std::shared_ptr<Session>& session,
                                              const wire::WireRequest& request,
                                              wire::WireResponse& response) {
  switch (request.id) {
    case wire::MessageId::SHUTDOWN:
      response.outcome = make_outcome(OutcomeCode::OK, "shutdown requested");
      return make_outcome(OutcomeCode::OK, std::string());
    case wire::MessageId::REGISTER_PUBLISHER: {
      // The registration binds to this connection's server-assigned session id.
      response.outcome = engine_.register_publisher(request.context.publisher,
                                                    request.context.worker_boot, request.scope,
                                                    session->id);
      if (response.outcome.succeeded()) {
        std::lock_guard<std::mutex> guard(sessions_mutex_);
        session->publisher = request.context.publisher;
        session->worker_boot = request.context.worker_boot;
        session->has_registration = true;
      }
      return make_outcome(OutcomeCode::OK, std::string());
    }
    default:
      break;
  }
  // Every remaining mutation is bound to the connection that issued it.
  if (requires_session(request.id) && !(request.context.session == session->id)) {
    response.outcome = make_rejection(
        OutcomeCode::UNAUTHORIZED_CALLER,
        "request session identity does not match the connection session " + session->id.str());
    return make_outcome(OutcomeCode::OK, std::string());
  }
  switch (request.id) {
    case wire::MessageId::CREATE_SET:
      response.outcome = engine_.create_set(request.context, request.key, request.options);
      break;
    case wire::MessageId::ADD_MEMBER:
      response.outcome = engine_.add_member(request.context, request.set_id, request.path_id,
                                            request.path_authority_generation);
      break;
    case wire::MessageId::ADD_MEMBERS:
      response.outcome =
          engine_.add_members(request.context, request.set_id, request.members);
      break;
    case wire::MessageId::REMOVE_MEMBER:
      response.outcome =
          engine_.remove_member(request.context, request.set_id, request.member_id, request.text);
      break;
    case wire::MessageId::WITHDRAW_MEMBER:
      response.outcome = engine_.withdraw_member(request.context, request.set_id,
                                                 request.member_id, request.text);
      break;
    case wire::MessageId::REPLACE_MEMBER:
      response.outcome = engine_.replace_member(request.context, request.set_id,
                                                request.member_id, request.path_id,
                                                request.path_authority_generation, request.text);
      break;
    case wire::MessageId::SET_MINIMUM:
      response.outcome =
          engine_.set_minimum_usable_members(request.context, request.set_id, request.number);
      break;
    case wire::MessageId::SET_CONDITIONAL_POLICY:
      response.outcome =
          engine_.set_conditional_authority_policy(request.context, request.set_id, request.flag);
      break;
    case wire::MessageId::SET_ADMIN_ENABLE:
      response.outcome = engine_.set_admin_enabled(request.context, request.set_id, true);
      break;
    case wire::MessageId::SET_ADMIN_DISABLE:
      response.outcome = engine_.set_admin_enabled(request.context, request.set_id, false);
      break;
    case wire::MessageId::MEMBER_ADMIN_ENABLE:
      response.outcome = engine_.set_member_admin_enabled(request.context, request.set_id,
                                                          request.member_id, true);
      break;
    case wire::MessageId::MEMBER_ADMIN_DISABLE:
      response.outcome = engine_.set_member_admin_enabled(request.context, request.set_id,
                                                          request.member_id, false);
      break;
    case wire::MessageId::REVALIDATE_SET:
      response.outcome = engine_.revalidate_set(request.context, request.set_id);
      break;
    case wire::MessageId::REVALIDATE_MEMBER:
      response.outcome =
          engine_.revalidate_member(request.context, request.set_id, request.member_id);
      break;
    case wire::MessageId::REVOKE_SET:
      response.outcome = engine_.revoke_set(request.context, request.set_id,
                                            request.revocation_reason, request.text);
      break;
    case wire::MessageId::RETIRE_SET:
      response.outcome = engine_.retire_set(request.context, request.set_id, request.text);
      break;
    case wire::MessageId::SUPERSEDE_SET: {
      const auto successor = MultipathSetId::parse(request.text);
      if (!successor.has_value()) {
        response.outcome = make_rejection(OutcomeCode::MALFORMED_REQUEST,
                                          "supersede request carries an invalid successor");
        break;
      }
      response.outcome = engine_.supersede_set(request.context, request.set_id, *successor);
      break;
    }
    case wire::MessageId::ADVANCE_SET_STATE:
      switch (request.state_action) {
        case wire::SetStateAction::PUBLISH:
          response.outcome = engine_.publish_set(request.context, request.set_id);
          break;
        case wire::SetStateAction::WITHDRAW:
          response.outcome =
              engine_.withdraw_set(request.context, request.set_id, request.text);
          break;
        case wire::SetStateAction::COMPLETE_WITHDRAWAL:
          response.outcome = engine_.complete_withdrawal(request.context, request.set_id);
          break;
      }
      break;
    case wire::MessageId::APPLY_PATH_AUTHORITY:
    case wire::MessageId::DECLARE_PATH_AUTHORITY: {
      PathAuthorityView view;
      view.path = request.path_id;
      view.generation = request.path_authority_generation;
      view.state = request.path_state;
      response.outcome = request.id == wire::MessageId::DECLARE_PATH_AUTHORITY
                             ? engine_.declare_path_authority(request.context, view)
                             : engine_.apply_path_authority(request.context, view);
      break;
    }
    case wire::MessageId::REFRESH_PATH:
      response.outcome = engine_.refresh_path(request.context, request.path_id);
      break;
    case wire::MessageId::EPOCH_ADVANCE: {
      const auto expected = CoordinatorEpoch::from_value(request.number);
      if (!expected.has_value()) {
        response.outcome = make_rejection(OutcomeCode::MALFORMED_REQUEST,
                                          "epoch advance request carries an impossible epoch");
        break;
      }
      response.outcome =
          engine_.advance_epoch(request.context.publisher, request.context.worker_boot,
                                request.context.session, *expected, request.context.attempt);
      break;
    }
    case wire::MessageId::LIST_SETS:
      response.set_ids = engine_.list_sets();
      response.outcome = make_outcome(OutcomeCode::OK,
                                      "listed " + std::to_string(response.set_ids.size()) +
                                          " set(s)");
      break;
    case wire::MessageId::QUERY_SET: {
      const auto snapshot = engine_.snapshot(request.set_id);
      if (!snapshot.has_value()) {
        response.outcome = make_rejection(OutcomeCode::SET_NOT_FOUND,
                                          "no such set: " + request.set_id.str());
        break;
      }
      response.snapshot = snapshot;
      response.outcome = make_outcome(OutcomeCode::OK, "snapshot of " + request.set_id.str());
      break;
    }
    case wire::MessageId::SNAPSHOT_REQUEST: {
      const auto snapshot = engine_.historical_snapshot(request.set_id, request.snapshot_id);
      if (!snapshot.has_value()) {
        response.outcome = make_rejection(OutcomeCode::SET_NOT_FOUND,
                                          "no retained snapshot " + request.snapshot_id.str() +
                                              " for set " + request.set_id.str());
        break;
      }
      response.snapshot = snapshot;
      response.outcome = make_outcome(OutcomeCode::OK, "historical snapshot");
      break;
    }
    case wire::MessageId::EXPLAIN_SET: {
      const auto explanation = engine_.explain_set(request.set_id);
      if (!explanation.has_value()) {
        response.outcome = make_rejection(OutcomeCode::SET_NOT_FOUND,
                                          "no such set: " + request.set_id.str());
        break;
      }
      response.explanation = explanation;
      response.outcome = make_outcome(OutcomeCode::OK, "explanation of " + request.set_id.str());
      break;
    }
    case wire::MessageId::HELLO:
    case wire::MessageId::HELLO_ACK:
    case wire::MessageId::SNAPSHOT_RESPONSE:
    case wire::MessageId::FENCE_NOTICE:
    case wire::MessageId::RESULT:
    case wire::MessageId::ERROR:
    case wire::MessageId::REGISTER_PUBLISHER:
    case wire::MessageId::SHUTDOWN:
      response.outcome = make_rejection(OutcomeCode::UNSUPPORTED_OPERATION,
                                        "message is not dispatched by the coordinator");
      break;
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

void MultipathFabricServer::session_loop(const std::shared_ptr<Session>& session) {
  // The coordinator announces the connection session identity and the governing
  // epoch before the client sends anything. A later HELLO refreshes the epoch
  // without changing the session.
  if (!send_hello_ack(session).succeeded()) {
    return;
  }
  SessionScratch scratch;
  while (!stopping_.load()) {
    if (!handle_frame(session, scratch)) {
      return;
    }
  }
}

bool MultipathFabricServer::handle_frame(const std::shared_ptr<Session>& session,
                                         SessionScratch& scratch) {
  std::size_t received = 0;
  const FabricOutcome header_read = net::socket_recv_exact(
      *session->socket, scratch.header.data(), scratch.header.size(), config_.poll_interval_ms,
      config_.frame_total_timeout_ms, &stopping_, received);
  if (!header_read.succeeded()) {
    if (header_read.code == OutcomeCode::PROTOCOL_ERROR && received == 0) {
      return false;  // clean peer close
    }
    scratch.response->outcome = make_rejection(header_read.code, header_read.detail);
    (void)send_frame(session, wire::MessageId::ERROR, *scratch.response);
    return false;
  }
  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t payload_length = 0;
  const FabricOutcome header_result = wire::decode_header(
      scratch.header.data(), scratch.header.size(), config_.limits.max_frame_bytes, id,
      payload_length);
  if (!header_result.succeeded()) {
    {
      std::lock_guard<std::mutex> guard(statistics_mutex_);
      ++statistics_.frames_rejected;
    }
    scratch.response->outcome = header_result;
    (void)send_frame(session, wire::MessageId::ERROR, *scratch.response);
    return false;
  }
  scratch.payload.assign(payload_length, 0);
  if (payload_length > 0) {
    std::size_t payload_received = 0;
    const FabricOutcome payload_read = net::socket_recv_exact(
        *session->socket, scratch.payload.data(), scratch.payload.size(),
        config_.poll_interval_ms, config_.frame_total_timeout_ms, &stopping_, payload_received);
    if (!payload_read.succeeded()) {
      scratch.response->outcome = make_rejection(payload_read.code, payload_read.detail);
      (void)send_frame(session, wire::MessageId::ERROR, *scratch.response);
      return false;
    }
  }
  const FabricOutcome integrity =
      wire::verify_integrity(scratch.header.data(), scratch.header.size(), scratch.payload);
  if (!integrity.succeeded()) {
    {
      std::lock_guard<std::mutex> guard(statistics_mutex_);
      ++statistics_.frames_rejected;
    }
    scratch.response->outcome = integrity;
    (void)send_frame(session, wire::MessageId::ERROR, *scratch.response);
    return false;
  }
  {
    std::lock_guard<std::mutex> guard(statistics_mutex_);
    ++statistics_.frames_received;
  }

  if (id == wire::MessageId::HELLO) {
    return send_hello_ack(session).succeeded();
  }

  detail::ByteReader reader(scratch.payload.data(), scratch.payload.size());
  wire::WireRequest& request = *scratch.request;
  const FabricOutcome decoded = wire::decode_request(id, reader, request);
  if (!decoded.succeeded() || !reader.at_end()) {
    {
      std::lock_guard<std::mutex> guard(statistics_mutex_);
      ++statistics_.frames_rejected;
    }
    scratch.response->outcome =
        decoded.succeeded()
            ? make_rejection(OutcomeCode::FRAMING_ERROR,
                             "request payload has " + std::to_string(reader.remaining()) +
                                 " trailing byte(s) after the declared fields")
            : decoded;
    (void)send_frame(session, wire::MessageId::ERROR, *scratch.response);
    return false;
  }

  wire::WireResponse& response = *scratch.response;
  const FabricOutcome dispatch_result = dispatch(session, request, response);
  if (!dispatch_result.succeeded()) {
    response.outcome = dispatch_result;
  } else if (response.outcome.succeeded() && config_.on_committed_mutation) {
    // Invoked outside every engine lock, by contract.
    config_.on_committed_mutation();
  }
  if (!send_frame(session, wire::MessageId::RESULT, response).succeeded()) {
    return false;
  }
  return id != wire::MessageId::SHUTDOWN;
}
}  // namespace multipath_fabric
