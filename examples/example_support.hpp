// Shared helpers for the Multipath Fabric examples.
//
// Every example uses the public API only.
#ifndef MPF_EXAMPLE_SUPPORT_HPP
#define MPF_EXAMPLE_SUPPORT_HPP

#include <cstdint>
#include <iostream>
#include <string>

#include "multipath_fabric/multipath_fabric.hpp"

namespace mpf_example {

inline std::uint64_t g_failures = 0;

inline void expect(bool condition, const std::string& message) {
  if (!condition) {
    ++g_failures;
    std::cout << "EXPECTATION FAILED: " << message << '\n';
  }
}

inline void line(const std::string& text) { std::cout << text << '\n'; }

inline int finish(const std::string& name) {
  if (g_failures == 0) {
    std::cout << name << " OK" << '\n';
    return 0;
  }
  std::cout << name << " FAILED " << g_failures << " expectation(s)" << '\n';
  return 1;
}

// A minimal publisher bootstrap shared by every example.
class Publisher {
 public:
  Publisher(multipath_fabric::FabricEngine& engine, const std::string& publisher_id,
            const std::string& boot_id, const std::string& fabric, const std::string& name_space,
            const std::string& session_label = "1")
      : engine_(engine) {
    publisher_ = multipath_fabric::PublisherId::require(publisher_id);
    boot_ = multipath_fabric::WorkerBootId::require(boot_id);
    session_ = multipath_fabric::SessionId::require("example-session-" + session_label);
    scope_.fabric = multipath_fabric::FabricId::require(fabric);
    scope_.name_space = multipath_fabric::MultipathNamespace::require(name_space);
    registered_ = engine_
                      .register_publisher(publisher_, boot_, scope_, session_)
                      .succeeded();
  }

  [[nodiscard]] bool registered() const noexcept { return registered_; }
  [[nodiscard]] const multipath_fabric::PublisherId& id() const noexcept { return publisher_; }
  [[nodiscard]] const multipath_fabric::WorkerBootId& boot() const noexcept { return boot_; }
  [[nodiscard]] const multipath_fabric::SessionId& session() const noexcept { return session_; }
  [[nodiscard]] const multipath_fabric::AuthorityScope& scope() const noexcept { return scope_; }

  [[nodiscard]] multipath_fabric::MutationContext context() {
    // Mutation attempt identities are unique per coordinator, so the example
    // draws them from a process-wide counter rather than a per-instance one.
    static std::uint64_t global_count = 0;
    multipath_fabric::MutationContext value;
    value.epoch = engine_.epoch();
    value.publisher = publisher_;
    value.worker_boot = boot_;
    value.session = session_;
    value.attempt = multipath_fabric::MutationAttemptId::require(
        "example-attempt-" + multipath_fabric::process_nonce() + "-" +
        std::to_string(++global_count) + "-" + std::to_string(++count_));
    return value;
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

 private:
  multipath_fabric::FabricEngine& engine_;
  multipath_fabric::PublisherId publisher_;
  multipath_fabric::WorkerBootId boot_;
  multipath_fabric::SessionId session_;
  multipath_fabric::AuthorityScope scope_;
  std::uint64_t count_ = 0;
  bool registered_ = false;
};

}  // namespace mpf_example

#endif  // MPF_EXAMPLE_SUPPORT_HPP
