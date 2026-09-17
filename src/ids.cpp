#include "multipath_fabric/ids.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <random>
#include <sstream>

namespace multipath_fabric {
namespace {

std::mutex g_nonce_mutex;
std::string g_nonce;

[[nodiscard]] std::string build_process_nonce() {
  std::random_device device;
  std::mt19937_64 engine(static_cast<std::uint64_t>(device()) ^
                         static_cast<std::uint64_t>(
                             std::chrono::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<std::uint64_t> distribution;
  const std::uint64_t value = distribution(engine);
  std::ostringstream stream;
  stream << std::hex << value;
  return stream.str();
}

}  // namespace

const std::string& process_nonce() {
  std::lock_guard<std::mutex> guard(g_nonce_mutex);
  if (g_nonce.empty()) {
    g_nonce = build_process_nonce();
  }
  return g_nonce;
}

IdFactory::IdFactory(std::string prefix) : prefix_(std::move(prefix)), nonce_(process_nonce()) {}

std::string IdFactory::compose(std::string_view kind, std::uint64_t counter) const {
  std::ostringstream stream;
  stream << prefix_ << '-' << kind << '-' << nonce_ << '-' << counter;
  return stream.str();
}

MultipathSetId IdFactory::next_set_id() noexcept {
  const std::uint64_t value = ++counter_;
  // The composed value is ASCII alphanumeric plus '-', which the identity
  // grammar accepts, and is far below the domain bound.
  return MultipathSetId::require(compose("set", value));
}

MultipathMemberId IdFactory::next_member_id() noexcept {
  const std::uint64_t value = ++counter_;
  return MultipathMemberId::require(compose("mem", value));
}

WorkerBootId IdFactory::next_worker_boot_id() noexcept {
  const std::uint64_t value = ++counter_;
  return WorkerBootId::require(compose("boot", value));
}

SessionId IdFactory::next_session_id() noexcept {
  const std::uint64_t value = ++counter_;
  return SessionId::require(compose("sess", value));
}

}  // namespace multipath_fabric
