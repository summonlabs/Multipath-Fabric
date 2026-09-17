// Shared fixtures for the Multipath Fabric test suite.
#ifndef MPF_TEST_SUPPORT_HPP
#define MPF_TEST_SUPPORT_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_framework.hpp"

namespace mpf_test {

// In-process fabric fixture with one registered publisher and a helper for
// declaring Path Authority views through the coordinator surface.
class FabricFixture {
 public:
  explicit FabricFixture(std::uint64_t seed = 1)
      : engine_(), publisher_(multipath_fabric::PublisherId::require("publisher-test")),
        boot_(multipath_fabric::WorkerBootId::require("boot-test-1")),
        session_(multipath_fabric::SessionId::require("session-test-1")),
        random_(seed) {
    scope_.fabric = multipath_fabric::FabricId::require("fabric-test");
    scope_.name_space = multipath_fabric::MultipathNamespace::require("ns-test");
    const multipath_fabric::FabricOutcome registered =
        engine_.register_publisher(publisher_, boot_, scope_, session_);
    registered_ = registered.succeeded();
  }

  [[nodiscard]] multipath_fabric::FabricEngine& engine() { return engine_; }
  [[nodiscard]] const multipath_fabric::FabricEngine& engine() const { return engine_; }
  [[nodiscard]] bool registered() const noexcept { return registered_; }
  [[nodiscard]] const multipath_fabric::PublisherId& publisher() const noexcept {
    return publisher_;
  }
  [[nodiscard]] const multipath_fabric::WorkerBootId& boot() const noexcept { return boot_; }
  [[nodiscard]] const multipath_fabric::SessionId& session() const noexcept { return session_; }
  [[nodiscard]] const multipath_fabric::AuthorityScope& scope() const noexcept { return scope_; }

  [[nodiscard]] multipath_fabric::MutationContext context() {
    multipath_fabric::MutationContext value;
    value.epoch = engine_.epoch();
    value.publisher = publisher_;
    value.worker_boot = boot_;
    value.session = session_;
    value.attempt = multipath_fabric::MutationAttemptId::require("attempt-" +
                                                                 std::to_string(++attempt_));
    return value;
  }

  [[nodiscard]] multipath_fabric::MultipathSetId create_set(
      const std::string& name, std::uint64_t minimum,
      bool admin_enabled = true, bool conditional = false) {
    multipath_fabric::SetKey key;
    key.fabric = scope_.fabric;
    key.name_space = scope_.name_space;
    key.name = multipath_fabric::MultipathSetName::require(name);
    multipath_fabric::SetOptions options;
    options.minimum_usable_members = minimum;
    options.admin_enabled = admin_enabled;
    options.conditional_authority_permitted = conditional;
    const multipath_fabric::FabricOutcome outcome = engine_.create_set(context(), key, options);
    return outcome.set_id.value_or(multipath_fabric::MultipathSetId{});
  }

  [[nodiscard]] multipath_fabric::FabricOutcome declare(
      const std::string& path, std::uint64_t generation,
      multipath_fabric::PathAuthorityState state =
          multipath_fabric::PathAuthorityState::AUTHORIZED) {
    multipath_fabric::PathAuthorityView view;
    view.path = multipath_fabric::PathId::require(path);
    view.generation = multipath_fabric::PathAuthorityGeneration::require(generation);
    view.state = state;
    return engine_.declare_path_authority(context(), view);
  }

  [[nodiscard]] multipath_fabric::FabricOutcome publish(
      const multipath_fabric::MultipathSetId& set_id) {
    return engine_.publish_set(context(), set_id);
  }

  [[nodiscard]] multipath_fabric::FabricOutcome add_member(
      const multipath_fabric::MultipathSetId& set_id, const std::string& path,
      std::uint64_t generation) {
    return engine_.add_member(context(), set_id, multipath_fabric::PathId::require(path),
                              multipath_fabric::PathAuthorityGeneration::require(generation));
  }

  [[nodiscard]] multipath_fabric::FabricOutcome revalidate(
      const multipath_fabric::MultipathSetId& set_id) {
    return engine_.revalidate_set(context(), set_id);
  }

  [[nodiscard]] std::uint64_t next_random(std::uint64_t bound) {
    return random_.below(bound);
  }

  [[nodiscard]] mpf_test::Random& random() noexcept { return random_; }

  // Convenience: publish a set with N authorized members at generation 1.
  [[nodiscard]] multipath_fabric::MultipathSetId build_set(const std::string& name,
                                                            std::uint64_t minimum,
                                                            std::uint64_t members) {
    const multipath_fabric::MultipathSetId set_id = create_set(name, minimum);
    if (!set_id.valid()) {
      return set_id;
    }
    if (!publish(set_id).succeeded()) {
      return set_id;
    }
    for (std::uint64_t i = 0; i < members; ++i) {
      const std::string path = "path-" + name + "-" + std::to_string(i);
      (void)declare(path, 1);
      (void)add_member(set_id, path, 1);
    }
    return set_id;
  }

 private:
  multipath_fabric::FabricEngine engine_;
  multipath_fabric::PublisherId publisher_;
  multipath_fabric::WorkerBootId boot_;
  multipath_fabric::SessionId session_;
  multipath_fabric::AuthorityScope scope_;
  std::uint64_t attempt_ = 0;
  bool registered_ = false;
  mpf_test::Random random_;
};

// Process-unique temporary directory. The directory name carries the process
// nonce and a monotonic counter so parallel test binaries never collide.
class TempDirectory {
 public:
  explicit TempDirectory(const std::string& label) {
    static std::atomic<std::uint64_t> counter{0};
    const std::uint64_t index = ++counter;
    base_ = std::filesystem::temp_directory_path() /
            ("mpf-test-" + label + "-" + multipath_fabric::process_nonce() + "-" +
             std::to_string(index));
    std::error_code error;
    std::filesystem::remove_all(base_, error);
    std::filesystem::create_directories(base_, error);
  }

  ~TempDirectory() {
    std::error_code error;
    std::filesystem::remove_all(base_, error);
  }

  TempDirectory(const TempDirectory&) = delete;
  TempDirectory& operator=(const TempDirectory&) = delete;

  [[nodiscard]] std::string path(const std::string& name) const {
    return (base_ / name).string();
  }
  [[nodiscard]] const std::filesystem::path& base() const noexcept { return base_; }

 private:
  std::filesystem::path base_;
};

[[nodiscard]] inline std::vector<std::uint8_t> read_bytes(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(stream)),
                                   std::istreambuf_iterator<char>());
}

inline void write_bytes(const std::string& path, const std::vector<std::uint8_t>& data) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
}

[[nodiscard]] inline std::string read_all(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::string text;
  std::string line;
  while (std::getline(stream, line)) {
    text += line;
    text += '\n';
  }
  return text;
}

[[nodiscard]] inline std::string read_text(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::string text;
  std::getline(stream, text);
  return text;
}

}  // namespace mpf_test

#endif  // MPF_TEST_SUPPORT_HPP
