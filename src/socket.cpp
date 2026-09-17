#include "multipath_fabric/socket.hpp"

#include <chrono>
#include <mutex>

#if defined(_WIN32)
#include <winsock2.h>
// Static analysis helper annotations on Microsoft's own SDK declarations are
// corrected in ws2tcpip.h:
//
//   ws2tcpip.h(968): warning C6101: Returning uninitialized memory '*Mtu'.
//
// The declaration is part of the external Windows SDK and cannot be fixed here.
// The suppression is scoped to this single external header include; no
// first-party code is exempted and no other warning is affected.
#pragma warning(push)
#pragma warning(disable : 6101)
#include <ws2tcpip.h>
#pragma warning(pop)
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace multipath_fabric::net {
namespace {

std::once_flag g_transport_once;
bool g_transport_ok = false;

#if defined(_WIN32)
void close_native(native_socket handle) noexcept {
  if (handle != invalid_socket) {
    ::closesocket(static_cast<SOCKET>(handle));
  }
}
#else
void close_native(native_socket handle) noexcept {
  if (handle != invalid_socket) {
    ::close(handle);
  }
}
#endif

[[nodiscard]] FabricOutcome last_error(const std::string& context) {
#if defined(_WIN32)
  return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                        context + " failed with WSA error " + std::to_string(::WSAGetLastError()));
#else
  return make_rejection(OutcomeCode::PROTOCOL_ERROR, context + " failed");
#endif
}

}  // namespace

void ensure_transport_initialised() {
  std::call_once(g_transport_once, []() {
#if defined(_WIN32)
    WSADATA data{};
    g_transport_ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    g_transport_ok = true;
#endif
  });
}

Socket::~Socket() { close(); }

Socket::Socket(Socket&& other) noexcept : handle_(other.handle_) {
  other.handle_ = invalid_socket;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    handle_ = other.handle_;
    other.handle_ = invalid_socket;
  }
  return *this;
}

void Socket::close() noexcept {
  if (handle_ != invalid_socket) {
    close_native(handle_);
    handle_ = invalid_socket;
  }
}

void Socket::interrupt() noexcept {
  if (handle_ != invalid_socket) {
#if defined(_WIN32)
    ::shutdown(static_cast<SOCKET>(handle_), SD_BOTH);
#else
    ::shutdown(handle_, SHUT_RDWR);
#endif
  }
}

void Socket::set_nodelay(bool enabled) noexcept {
  if (handle_ == invalid_socket) {
    return;
  }
  const int value = enabled ? 1 : 0;
#if defined(_WIN32)
  ::setsockopt(static_cast<SOCKET>(handle_), IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&value), sizeof(value));
#else
  ::setsockopt(handle_, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
#endif
}

FabricOutcome tcp_listen(const std::string& host, std::uint16_t port, Socket& out,
                         std::uint16_t& bound_port) {
  ensure_transport_initialised();
  if (!g_transport_ok) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "transport initialisation failed");
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  const std::string node = host.empty() ? std::string("127.0.0.1") : host;
  if (::getaddrinfo(node.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "cannot resolve listen address " + node + ":" + service);
  }
  Socket listener;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const native_socket handle = static_cast<native_socket>(::socket(
        candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (handle == invalid_socket) {
      continue;
    }
    Socket probe(handle);
    const int reuse = 1;
#if defined(_WIN32)
    ::setsockopt(static_cast<SOCKET>(handle), SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));
#else
    ::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
    if (::bind(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) != 0) {
      continue;
    }
    if (::listen(handle, 32) != 0) {
      continue;
    }
    listener = std::move(probe);
    break;
  }
  ::freeaddrinfo(results);
  if (!listener.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "cannot bind a listening socket on " + node + ":" + service);
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
  if (::getsockname(static_cast<SOCKET>(listener.native()),
                    reinterpret_cast<sockaddr*>(&address), &length) != 0) {
#else
  socklen_t length = sizeof(address);
  if (::getsockname(listener.native(), reinterpret_cast<sockaddr*>(&address), &length) != 0) {
#endif
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "cannot read the bound port");
  }
  bound_port = ntohs(address.sin_port);
  out = std::move(listener);
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome tcp_accept(const Socket& listener, Socket& out) {
  if (!listener.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "listener socket is closed");
  }
  sockaddr_in address{};
#if defined(_WIN32)
  int length = sizeof(address);
  const native_socket accepted =
      static_cast<native_socket>(::accept(static_cast<SOCKET>(listener.native()),
                                          reinterpret_cast<sockaddr*>(&address), &length));
#else
  socklen_t length = sizeof(address);
  const native_socket accepted =
      ::accept(listener.native(), reinterpret_cast<sockaddr*>(&address), &length);
#endif
  if (accepted == invalid_socket) {
    return last_error("accept");
  }
  out = Socket(accepted);
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome tcp_connect(const std::string& host, std::uint16_t port, std::uint32_t timeout_ms,
                          Socket& out) {
  ensure_transport_initialised();
  if (!g_transport_ok) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "transport initialisation failed");
  }
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* results = nullptr;
  const std::string service = std::to_string(port);
  if (::getaddrinfo(host.c_str(), service.c_str(), &hints, &results) != 0 || results == nullptr) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "cannot resolve " + host + ":" + service);
  }
  Socket client;
  for (addrinfo* candidate = results; candidate != nullptr; candidate = candidate->ai_next) {
    const native_socket handle = static_cast<native_socket>(::socket(
        candidate->ai_family, candidate->ai_socktype, candidate->ai_protocol));
    if (handle == invalid_socket) {
      continue;
    }
    Socket probe(handle);
    if (::connect(handle, candidate->ai_addr, static_cast<int>(candidate->ai_addrlen)) == 0) {
      client = std::move(probe);
      break;
    }
  }
  ::freeaddrinfo(results);
  if (!client.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                          "cannot connect to " + host + ":" + service);
  }
  (void)timeout_ms;
  client.set_nodelay(true);
  out = std::move(client);
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome socket_wait_readable(const Socket& socket, std::uint32_t timeout_ms,
                                   const std::atomic<bool>* stop_flag, bool& readable) {
  readable = false;
  if (!socket.valid()) {
    return make_rejection(OutcomeCode::PROTOCOL_ERROR, "socket is closed");
  }
  const std::uint32_t slice = timeout_ms == 0 ? 1U : (timeout_ms > 100U ? 100U : timeout_ms);
  std::uint32_t waited = 0;
  for (;;) {
    if (stop_flag != nullptr && stop_flag->load()) {
      return make_rejection(OutcomeCode::PROTOCOL_ERROR, "session is stopping");
    }
#if defined(_WIN32)
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(static_cast<SOCKET>(socket.native()), &read_set);
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = static_cast<long>(slice) * 1000L;
    const int ready = ::select(0, &read_set, nullptr, nullptr, &tv);
#else
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(socket.native(), &read_set);
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = static_cast<long>(slice) * 1000L;
    const int ready = ::select(socket.native() + 1, &read_set, nullptr, nullptr, &tv);
#endif
    if (ready > 0) {
      readable = true;
      return make_outcome(OutcomeCode::OK, std::string());
    }
    if (ready < 0) {
      return last_error("select");
    }
    waited += slice;
    if (timeout_ms != 0 && waited >= timeout_ms) {
      // A timeout is not a failure: the caller decides whether the absence of
      // data means "idle" or "stalled frame".
      readable = false;
      return make_outcome(OutcomeCode::OK, std::string());
    }
  }
}

FabricOutcome socket_send_all(const Socket& socket, const std::uint8_t* data, std::size_t size,
                              std::uint32_t timeout_ms, const std::atomic<bool>* stop_flag) {
  std::size_t sent = 0;
  const auto deadline = timeout_ms == 0
                            ? std::chrono::steady_clock::time_point::max()
                            : std::chrono::steady_clock::now() +
                                  std::chrono::milliseconds(timeout_ms);
  while (sent < size) {
    if (stop_flag != nullptr && stop_flag->load()) {
      return make_rejection(OutcomeCode::PROTOCOL_ERROR, "session is stopping");
    }
    if (std::chrono::steady_clock::now() > deadline) {
      return make_rejection(OutcomeCode::SESSION_TIMEOUT,
                            "send of " + std::to_string(size) + " bytes did not complete within " +
                                std::to_string(timeout_ms) + " ms");
    }
#if defined(_WIN32)
    const int chunk = ::send(static_cast<SOCKET>(socket.native()),
                             reinterpret_cast<const char*>(data + sent),
                             static_cast<int>(size - sent), 0);
#else
    const int chunk = static_cast<int>(
        ::send(socket.native(), data + sent, size - sent, MSG_NOSIGNAL));
#endif
    if (chunk > 0) {
      sent += static_cast<std::size_t>(chunk);
      continue;
    }
    if (chunk == 0) {
      return make_rejection(OutcomeCode::PROTOCOL_ERROR, "peer closed the connection");
    }
    bool readable = false;
    const FabricOutcome wait = socket_wait_readable(socket, timeout_ms, stop_flag, readable);
    if (!wait.succeeded()) {
      return wait;
    }
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome socket_recv_exact(const Socket& socket, std::uint8_t* data, std::size_t size,
                                std::uint32_t poll_interval_ms, std::uint32_t frame_timeout_ms,
                                const std::atomic<bool>* stop_flag, std::size_t& received) {
  received = 0;
  bool frame_started = false;
  std::chrono::steady_clock::time_point frame_start;
  while (received < size) {
    bool readable = false;
    const FabricOutcome wait =
        socket_wait_readable(socket, poll_interval_ms, stop_flag, readable);
    if (!wait.succeeded()) {
      return (received > 0 || frame_started)
                 ? make_rejection(OutcomeCode::SESSION_TIMEOUT,
                                  "peer sent only " + std::to_string(received) + " of " +
                                      std::to_string(size) +
                                      " frame bytes before the frame budget expired")
                 : wait;
    }
    if (!readable) {
      // An idle peer that has not started a frame keeps its session; a peer that
      // started a frame and stalled is abandoned once the budget expires.
      if (frame_started && frame_timeout_ms != 0 &&
          std::chrono::steady_clock::now() - frame_start >
              std::chrono::milliseconds(frame_timeout_ms)) {
        return make_rejection(OutcomeCode::SESSION_TIMEOUT,
                              "peer stalled after " + std::to_string(received) + " of " +
                                  std::to_string(size) + " frame bytes");
      }
      continue;
    }
#if defined(_WIN32)
    const int chunk = ::recv(static_cast<SOCKET>(socket.native()),
                             reinterpret_cast<char*>(data + received),
                             static_cast<int>(size - received), 0);
#else
    const int chunk = static_cast<int>(::recv(socket.native(), data + received,
                                              size - received, 0));
#endif
    if (chunk > 0) {
      if (!frame_started) {
        frame_started = true;
        frame_start = std::chrono::steady_clock::now();
      }
      received += static_cast<std::size_t>(chunk);
      if (frame_timeout_ms != 0 &&
          std::chrono::steady_clock::now() - frame_start >
              std::chrono::milliseconds(frame_timeout_ms)) {
        return make_rejection(OutcomeCode::SESSION_TIMEOUT,
                              "frame receive exceeded the budget of " +
                                  std::to_string(frame_timeout_ms) + " ms after " +
                                  std::to_string(received) + " of " + std::to_string(size) +
                                  " bytes");
      }
      continue;
    }
    if (chunk == 0) {
      return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                            "peer closed the connection after " + std::to_string(received) +
                                " of " + std::to_string(size) + " frame bytes");
    }
    return last_error("recv");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

}  // namespace multipath_fabric::net
