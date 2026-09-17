// Coordinator server.
//
// The server owns the listening socket and one thread per session. It performs
// framing, integrity and structural validation only; every authority,
// generation, dependency and semantic decision belongs to FabricEngine.
//
// SESSION AUTHORITY
// -----------------
// The server assigns each connection a SessionId and returns it in HELLO_ACK.
// Every subsequent request must carry that exact session id, so a client cannot
// borrow another connection's session. When a session ends for any reason -
// clean disconnect, peer kill or protocol failure - the server fences every
// worker boot that registered on it, which is how real worker death becomes a
// permanent fence rather than a boolean.
#ifndef MULTIPATH_FABRIC_SERVER_HPP
#define MULTIPATH_FABRIC_SERVER_HPP

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "multipath_fabric/fabric.hpp"
#include "multipath_fabric/socket.hpp"
#include "multipath_fabric/wire.hpp"

namespace multipath_fabric {

// Portable "do not inline" attribute. Used where a large callee must not inflate
// the stack frame of a long-lived worker thread.
#if defined(_MSC_VER)
#define MPF_NOINLINE __declspec(noinline)
#else
#define MPF_NOINLINE __attribute__((noinline))
#endif

struct ServerConfig {
  Limits limits;
  // Invoked after every committed mutation dispatch, outside the engine lock.
  // The coordinator uses it to write the durable store through. It must not
  // call back into the server.
  std::function<void()> on_committed_mutation;
  std::string bind_host = "127.0.0.1";
  // Zero requests an ephemeral port; read it back through port().
  std::uint16_t port = 0;
  // Bounded per-frame receive budget. A peer that sends half a frame cannot pin
  // a session past this boundary; the session fails with SESSION_TIMEOUT.
  std::uint32_t frame_total_timeout_ms = 30000;
  std::uint32_t poll_interval_ms = 50;
  std::uint32_t send_timeout_ms = 30000;
};

struct ServerStatistics {
  std::uint64_t sessions_accepted = 0;
  std::uint64_t sessions_rejected = 0;
  std::uint64_t frames_received = 0;
  std::uint64_t frames_rejected = 0;
  std::uint64_t workers_fenced = 0;
};

class MultipathFabricServer {
 public:
  MultipathFabricServer(FabricEngine& engine, ServerConfig config);
  ~MultipathFabricServer();

  MultipathFabricServer(const MultipathFabricServer&) = delete;
  MultipathFabricServer& operator=(const MultipathFabricServer&) = delete;
  MultipathFabricServer(MultipathFabricServer&&) = delete;
  MultipathFabricServer& operator=(MultipathFabricServer&&) = delete;

  // Binds the listener and starts the accept thread. Returns a structured
  // rejection when the address cannot be bound.
  [[nodiscard]] FabricOutcome start();
  // Stops accepting, interrupts every live session and joins every thread.
  // Safe to call more than once and from any thread.
  void stop();

  [[nodiscard]] bool running() const noexcept { return running_.load(); }
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] std::size_t active_sessions() const;
  [[nodiscard]] ServerStatistics statistics() const;

 private:
  struct Session {
    SessionId id;
    std::shared_ptr<net::Socket> socket;
    std::thread thread;
    std::atomic<bool> done{false};
    PublisherId publisher;
    WorkerBootId worker_boot;
    bool has_registration = false;
  };

  // Per-connection scratch space. It is owned by the session thread but lives
  // on the heap so that a long-lived worker thread keeps a small stack: the
  // request and response envelopes alone are several kilobytes.
  struct SessionScratch {
    std::array<std::uint8_t, wire::frame_header_size> header{};
    std::vector<std::uint8_t> payload;
    std::unique_ptr<wire::WireRequest> request = std::make_unique<wire::WireRequest>();
    std::unique_ptr<wire::WireResponse> response = std::make_unique<wire::WireResponse>();
  };

  void accept_loop();
  void session_loop(const std::shared_ptr<Session>& session);
  // Reads, validates, dispatches and answers exactly one frame. Returns false
  // when the session must end. Kept out of line so its frame does not inflate
  // session_loop.
  MPF_NOINLINE [[nodiscard]] bool handle_frame(const std::shared_ptr<Session>& session,
                                               SessionScratch& scratch);
  [[nodiscard]] FabricOutcome send_hello_ack(const std::shared_ptr<Session>& session);
  void reap_finished_sessions(bool join_all);
  void end_session(const std::shared_ptr<Session>& session, const std::string& cause);
  MPF_NOINLINE [[nodiscard]] FabricOutcome send_frame(const std::shared_ptr<Session>& session,
                                                      wire::MessageId id,
                                                      const wire::WireResponse& response);
  // Kept out of line: the dispatch table allocates a large result frame, and a
  // session thread must keep a small, bounded stack.
  MPF_NOINLINE [[nodiscard]] FabricOutcome dispatch(const std::shared_ptr<Session>& session,
                                                    const wire::WireRequest& request,
                                                    wire::WireResponse& response);

  FabricEngine& engine_;
  ServerConfig config_;
  net::Socket listener_;
  std::thread accept_thread_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stopping_{false};
  std::uint16_t port_ = 0;
  IdFactory sessions_ids_{"sess"};

  mutable std::mutex sessions_mutex_;
  std::map<SessionId, std::shared_ptr<Session>> sessions_;

  mutable std::mutex statistics_mutex_;
  ServerStatistics statistics_;
};

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_SERVER_HPP
