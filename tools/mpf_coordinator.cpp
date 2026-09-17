// mpf_coordinator -- the Multipath Fabric coordinator process.
//
// Owns mutation authority for one deployment, speaks the framed wire protocol
// on loopback, persists the durable store through after every committed
// mutation and recovers conservatively on start.
#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "tool_common.hpp"

namespace {

std::atomic<bool> g_stop{false};

#if defined(_WIN32)
BOOL WINAPI console_handler(DWORD signal) {
  if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
    g_stop.store(true);
    return TRUE;
  }
  return FALSE;
}
#else
extern "C" void posix_handler(int) { g_stop.store(true); }
#endif

}  // namespace

int main(int argc, char** argv) {
  mpf_tool::Arguments arguments(argc, argv);
  if (arguments.has("--help")) {
    std::cout << "usage: mpf_coordinator [--store PATH] [--bind HOST] [--port N] "
                 "[--port-file PATH] [--frame-timeout-ms N] [--max-sessions N] "
                 "[--no-autosave] [--quiet]\n";
    return 0;
  }
  const std::string store = arguments.text("--store", "");
  const std::string bind_host = arguments.text("--bind", "127.0.0.1");
  const std::string port_file = arguments.text("--port-file", "");
  const bool autosave = !arguments.has("--no-autosave");
  const bool quiet = arguments.has("--quiet");
  const std::uint64_t port_number = arguments.number("--port", 0);
  const std::uint64_t frame_timeout = arguments.number("--frame-timeout-ms", 30000);
  const std::uint64_t max_sessions = arguments.number("--max-sessions", 0);

  multipath_fabric::ServerConfig config;
  config.bind_host = bind_host;
  config.port = static_cast<std::uint16_t>(port_number);
  config.frame_total_timeout_ms = static_cast<std::uint32_t>(frame_timeout);
  if (max_sessions != 0) {
    config.limits.max_sessions = max_sessions;
  }

  multipath_fabric::FabricEngine engine;
  if (!store.empty() && std::filesystem::exists(store)) {
    const multipath_fabric::FabricOutcome loaded = engine.load_store(store);
    if (!quiet) {
      std::cout << "LOAD " << loaded.render() << '\n';
    }
    if (!loaded.succeeded()) {
      std::cout << "EXIT LOAD_FAILED\n";
      return 3;
    }
  } else if (!quiet) {
    std::cout << "LOAD FRESH epoch=" << engine.epoch().value() << '\n';
  }

  if (autosave && !store.empty()) {
    config.on_committed_mutation = [&engine, &store]() {
      const multipath_fabric::FabricOutcome saved = engine.save_store(store);
      if (!saved.succeeded()) {
        std::cerr << "autosave failed: " << saved.render() << '\n';
      }
    };
  }

  multipath_fabric::MultipathFabricServer server(engine, std::move(config));
  const multipath_fabric::FabricOutcome started = server.start();
  if (!started.succeeded()) {
    std::cout << "EXIT " << started.render() << '\n';
    return 4;
  }
  if (!quiet) {
    std::cout << "LISTENING " << bind_host << ':' << server.port()
              << " epoch=" << engine.epoch().value() << '\n';
  }
  std::cout.flush();
  if (!port_file.empty() &&
      !mpf_tool::write_announcement(port_file, "READY " + std::to_string(server.port()) + " " +
                                                    std::to_string(engine.epoch().value()) +
                                                    "\n")) {
    std::cerr << "cannot write readiness announcement to " << port_file << '\n';
    server.stop();
    return 5;
  }

#if defined(_WIN32)
  std::signal(SIGINT, [](int) { g_stop.store(true); });
  std::signal(SIGTERM, [](int) { g_stop.store(true); });
  SetConsoleCtrlHandler(console_handler, TRUE);
#else
  std::signal(SIGINT, posix_handler);
  std::signal(SIGTERM, posix_handler);
#endif

  while (!g_stop.load()) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  server.stop();
  if (autosave && !store.empty()) {
    const multipath_fabric::FabricOutcome saved = engine.save_store(store);
    if (!quiet) {
      std::cout << "FINAL " << saved.render() << '\n';
    }
  }
  std::cout << "STOPPED sets=" << engine.set_count() << '\n';
  return 0;
}
