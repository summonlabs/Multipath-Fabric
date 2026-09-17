// Minimal blocking-socket transport with explicit bounded waits.
//
// Windows does not guarantee that shutdown() alone cancels a blocked recv(), so
// every receive path in Multipath Fabric uses select() with a bounded poll
// interval. Exceeding the configured frame-read budget produces a structured
// SESSION_TIMEOUT protocol failure; it is never an unbounded wait and it is
// never a test timeout.
#ifndef MULTIPATH_FABRIC_SOCKET_HPP
#define MULTIPATH_FABRIC_SOCKET_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "multipath_fabric/outcome.hpp"

namespace multipath_fabric::net {

#if defined(_WIN32)
using native_socket = std::uintptr_t;
inline constexpr native_socket invalid_socket = static_cast<native_socket>(~0ULL);
#else
using native_socket = int;
inline constexpr native_socket invalid_socket = -1;
#endif

// RAII socket handle. Move-only. Closing twice is safe.
class Socket {
 public:
  Socket() noexcept = default;
  explicit Socket(native_socket handle) noexcept : handle_(handle) {}
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept { return handle_ != invalid_socket; }
  [[nodiscard]] native_socket native() const noexcept { return handle_; }

  void close() noexcept;
  // Requests cancellation of a blocked operation on another thread and disables
  // further sends. Safe to call from a different thread than the one blocked in
  // a receive loop.
  void interrupt() noexcept;
  void set_nodelay(bool enabled) noexcept;

 private:
  native_socket handle_ = invalid_socket;
};

// One-time process-wide transport initialisation. Called automatically.
void ensure_transport_initialised();

// Creates a listening socket bound to host:port. Passing port 0 requests an
// ephemeral port, reported through bound_port.
[[nodiscard]] FabricOutcome tcp_listen(const std::string& host, std::uint16_t port,
                                       Socket& out, std::uint16_t& bound_port);

// Accepts one pending connection from a listening socket. The caller is
// responsible for only calling this once the listener reports readable.
[[nodiscard]] FabricOutcome tcp_accept(const Socket& listener, Socket& out);

// Connects with an explicit bounded connect timeout.
[[nodiscard]] FabricOutcome tcp_connect(const std::string& host, std::uint16_t port,
                                        std::uint32_t timeout_ms, Socket& out);

// Sends every byte, bounded by an explicit timeout. Fails when the socket is
// interrupted.
[[nodiscard]] FabricOutcome socket_send_all(const Socket& socket, const std::uint8_t* data,
                                            std::size_t size, std::uint32_t timeout_ms,
                                            const std::atomic<bool>* stop_flag);

// Receives exactly "size" bytes.
//
// poll_interval_ms is the wake-up granularity used to observe the stop flag, not
// a deadline. An idle peer that has sent nothing yet keeps its session open
// indefinitely: being idle is not a protocol failure.
//
// Once the first byte of a frame has arrived, that frame must complete within
// frame_timeout_ms. A peer that sends half a frame and then stalls therefore
// fails with a structured SESSION_TIMEOUT instead of pinning the session.
[[nodiscard]] FabricOutcome socket_recv_exact(const Socket& socket, std::uint8_t* data,
                                              std::size_t size, std::uint32_t poll_interval_ms,
                                              std::uint32_t frame_timeout_ms,
                                              const std::atomic<bool>* stop_flag,
                                              std::size_t& received);

// Waits up to timeout_ms for readability. Reaching the timeout is NOT an error:
// it returns success with readable = false, because an idle session is normal.
// The function fails only for a real socket error or when the stop flag is set.
[[nodiscard]] FabricOutcome socket_wait_readable(const Socket& socket,
                                                 std::uint32_t timeout_ms,
                                                 const std::atomic<bool>* stop_flag,
                                                 bool& readable);

}  // namespace multipath_fabric::net

#endif  // MULTIPATH_FABRIC_SOCKET_HPP
