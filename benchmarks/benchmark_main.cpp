// Multipath Fabric benchmarks.
//
// Every measurement counts completed operations only. The numbers are pure
// measurements of this machine and this build; they are not service level
// objectives and no physical fabric claim is derived from them.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"

namespace {

using multipath_fabric::FabricEngine;
using multipath_fabric::MutationContext;
using multipath_fabric::MultipathSetId;

class Timer {
 public:
  Timer() : start_(std::chrono::steady_clock::now()) {}
  [[nodiscard]] double seconds() const {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start_).count();
  }

 private:
  std::chrono::steady_clock::time_point start_;
};

void report(const std::string& name, std::uint64_t operations, double seconds) {
  const double per_second = seconds > 0 ? static_cast<double>(operations) / seconds : 0.0;
  const double micros = operations > 0 ? seconds * 1e6 / static_cast<double>(operations) : 0.0;
  std::cout << std::left << std::setw(46) << name << std::right << std::setw(12) << operations
            << " ops " << std::setw(12) << std::fixed << std::setprecision(2) << per_second
            << " ops/s " << std::setw(10) << std::setprecision(3) << micros << " us/op\n";
}

struct Harness {
  FabricEngine engine;
  multipath_fabric::PublisherId publisher;
  multipath_fabric::WorkerBootId boot;
  multipath_fabric::SessionId session;
  multipath_fabric::AuthorityScope scope;
  std::uint64_t attempts = 0;

  explicit Harness(multipath_fabric::FabricConfig config = multipath_fabric::FabricConfig{})
      : engine(std::move(config)) {
    publisher = multipath_fabric::PublisherId::require("bench-publisher");
    boot = multipath_fabric::WorkerBootId::require("bench-boot");
    session = multipath_fabric::SessionId::require("bench-session");
    scope.fabric = multipath_fabric::FabricId::require("bench-fabric");
    scope.name_space = multipath_fabric::MultipathNamespace::require("bench-ns");
    engine.register_publisher(publisher, boot, scope, session);
  }

  [[nodiscard]] MutationContext context() {
    MutationContext value;
    value.epoch = engine.epoch();
    value.publisher = publisher;
    value.worker_boot = boot;
    value.session = session;
    value.attempt = multipath_fabric::MutationAttemptId::require("bench-attempt-" +
                                                                 std::to_string(++attempts));
    return value;
  }

  void declare(const std::string& path, std::uint64_t generation = 1) {
    multipath_fabric::PathAuthorityView view;
    view.path = multipath_fabric::PathId::require(path);
    view.generation = multipath_fabric::PathAuthorityGeneration::require(generation);
    view.state = multipath_fabric::PathAuthorityState::AUTHORIZED;
    const multipath_fabric::FabricOutcome outcome = engine.declare_path_authority(context(), view);
    if (!outcome.succeeded()) {
      std::cerr << "declare_path_authority failed: " << outcome.render() << '\n';
      ++failures;
    }
  }

  std::uint64_t failures = 0;

  [[nodiscard]] MultipathSetId create(const std::string& name, std::uint64_t minimum = 1) {
    multipath_fabric::SetKey key;
    key.fabric = scope.fabric;
    key.name_space = scope.name_space;
    key.name = multipath_fabric::MultipathSetName::require(name);
    multipath_fabric::SetOptions options;
    options.minimum_usable_members = minimum;
    return engine.create_set(context(), key, options).set_id.value_or(MultipathSetId{});
  }
};

}  // namespace

int main() {
  std::cout << "Multipath Fabric " << multipath_fabric::version_string
            << " benchmarks (measurements only)\n";

  // -- single operation latency ---------------------------------------------
  {
    Harness harness;
    constexpr std::uint64_t kIterations = 2000;
    Timer timer;
    std::uint64_t created = 0;
    for (std::uint64_t index = 0; index < kIterations; ++index) {
      if (harness.create("latency-set-" + std::to_string(index)).valid()) {
        ++created;
      }
    }
    report("create_set", created, timer.seconds());
  }
  {
    Harness harness;
    constexpr std::uint64_t kSets = 200;
    constexpr std::uint64_t kMembers = 8;
    std::vector<MultipathSetId> sets;
    for (std::uint64_t index = 0; index < kSets; ++index) {
      const MultipathSetId set_id = harness.create("member-set-" + std::to_string(index));
      harness.engine.publish_set(harness.context(), set_id);
      sets.push_back(set_id);
      for (std::uint64_t member = 0; member < kMembers; ++member) {
        harness.declare("bench-path-" + std::to_string(index) + "-" + std::to_string(member));
      }
    }
    Timer timer;
    std::uint64_t operations = 0;
    for (std::size_t set_index = 0; set_index < sets.size(); ++set_index) {
      for (std::uint64_t member = 0; member < kMembers; ++member) {
        const std::string path = "bench-path-" + std::to_string(set_index) + "-" +
                                 std::to_string(member);
        if (harness.engine
                .add_member(harness.context(), sets[set_index],
                            multipath_fabric::PathId::require(path),
                            multipath_fabric::PathAuthorityGeneration::require(1))
                .succeeded()) {
          ++operations;
        }
      }
    }
    report("add_member", operations, timer.seconds());
  }
  {
    Harness harness;
    constexpr std::uint64_t kSets = 200;
    constexpr std::uint64_t kMembers = 8;
    std::vector<MultipathSetId> sets;
    for (std::uint64_t index = 0; index < kSets; ++index) {
      const MultipathSetId set_id = harness.create("query-set-" + std::to_string(index));
      harness.engine.publish_set(harness.context(), set_id);
      sets.push_back(set_id);
      for (std::uint64_t member = 0; member < kMembers; ++member) {
        const std::string path =
            "query-path-" + std::to_string(index) + "-" + std::to_string(member);
        harness.declare(path);
        harness.engine.add_member(harness.context(), set_id,
                                  multipath_fabric::PathId::require(path),
                                  multipath_fabric::PathAuthorityGeneration::require(1));
      }
    }
    constexpr std::uint64_t kIterations = 20000;
    Timer timer;
    std::uint64_t operations = 0;
    for (std::uint64_t index = 0; index < kIterations; ++index) {
      if (harness.engine.snapshot(sets[index % sets.size()]).has_value()) {
        ++operations;
      }
    }
    report("query_set (snapshot)", operations, timer.seconds());

    Timer digest_timer;
    std::uint64_t digest_operations = 0;
    for (std::uint64_t index = 0; index < kIterations; ++index) {
      if (harness.engine.snapshot(sets[index % sets.size()]).has_value()) {
        ++digest_operations;
      }
    }
    report("snapshot including semantic digest", digest_operations, digest_timer.seconds());

    Timer explain_timer;
    std::uint64_t explanations = 0;
    for (std::uint64_t index = 0; index < 2000; ++index) {
      if (harness.engine.explain_set(sets[index % sets.size()]).has_value()) {
        ++explanations;
      }
    }
    report("explain_set", explanations, explain_timer.seconds());

    Timer revalidate_timer;
    std::uint64_t revalidations = 0;
    for (const auto& set_id : sets) {
      if (harness.engine.revalidate_set(harness.context(), set_id).succeeded()) {
        ++revalidations;
      }
    }
    report("revalidate_set", revalidations, revalidate_timer.seconds());

    Timer diff_timer;
    std::uint64_t diffs = 0;
    for (const auto& set_id : sets) {
      if (harness.engine.diff_last_two(set_id).has_value()) {
        ++diffs;
      }
    }
    report("diff_last_two", diffs, diff_timer.seconds());
  }

  // -- reverse dependency invalidation --------------------------------------
  {
    Harness harness;
    constexpr std::uint64_t kSets = 500;
    constexpr std::uint64_t kMembers = 4;
    const std::string shared = "shared-path";
    std::vector<MultipathSetId> sets;
    for (std::uint64_t index = 0; index < kSets; ++index) {
      const MultipathSetId set_id = harness.create("fanout-set-" + std::to_string(index));
      harness.engine.publish_set(harness.context(), set_id);
      sets.push_back(set_id);
    }
    harness.declare(shared);
    for (const auto& set_id : sets) {
      harness.engine.add_member(harness.context(), set_id,
                                multipath_fabric::PathId::require(shared),
                                multipath_fabric::PathAuthorityGeneration::require(1));
    }
    for (std::uint64_t index = 0; index < kMembers; ++index) {
      const std::string path = "fanout-private-" + std::to_string(index);
      harness.declare(path);
      for (const auto& set_id : sets) {
        harness.engine.add_member(harness.context(), set_id,
                                  multipath_fabric::PathId::require(path),
                                  multipath_fabric::PathAuthorityGeneration::require(1));
      }
    }
    Timer timer;
    std::uint64_t operations = 0;
    for (std::uint64_t round = 0; round < 50; ++round) {
      multipath_fabric::PathAuthorityView view;
      view.path = multipath_fabric::PathId::require(shared);
      view.generation = multipath_fabric::PathAuthorityGeneration::require(1 + (round % 2));
      view.state = multipath_fabric::PathAuthorityState::AUTHORIZED;
      if (harness.engine.declare_path_authority(harness.context(), view).succeeded()) {
        ++operations;
      }
    }
    report("path invalidation over a large reverse index", operations, timer.seconds());
  }

  // -- scale ----------------------------------------------------------------
  {
    Harness harness;
    constexpr std::uint64_t kSets = 100000;
    Timer timer;
    std::uint64_t operations = 0;
    for (std::uint64_t index = 0; index < kSets; ++index) {
      if (harness.create("scale-set-" + std::to_string(index)).valid()) {
        ++operations;
      }
    }
    report("create_set at 100k population", operations, timer.seconds());

    Timer query_timer;
    constexpr std::uint64_t kIterations = 200000;
    std::uint64_t queries = 0;
    const std::vector<MultipathSetId> listed = harness.engine.list_sets();
    for (std::uint64_t index = 0; index < kIterations; ++index) {
      if (harness.engine.snapshot(listed[index % listed.size()]).has_value()) {
        ++queries;
      }
    }
    report("query_set at 100k population", queries, query_timer.seconds());

    const multipath_fabric::FabricIntegrityReport integrity = harness.engine.check_integrity();
    std::cout << "integrity at 100k sets: " << integrity.render() << '\n';
  }

  // -- persistence ----------------------------------------------------------
  {
    Harness harness;
    constexpr std::uint64_t kSets = 5000;
    for (std::uint64_t index = 0; index < kSets; ++index) {
      const MultipathSetId set_id = harness.create("store-set-" + std::to_string(index));
      harness.engine.publish_set(harness.context(), set_id);
      for (std::uint64_t member = 0; member < 4; ++member) {
        const std::string path =
            "store-path-" + std::to_string(index) + "-" + std::to_string(member);
        harness.declare(path);
        harness.engine.add_member(harness.context(), set_id,
                                  multipath_fabric::PathId::require(path),
                                  multipath_fabric::PathAuthorityGeneration::require(1));
      }
    }
    const std::filesystem::path store =
        std::filesystem::temp_directory_path() /
        ("mpf-benchmark-" + multipath_fabric::process_nonce() + ".bin");
    Timer save_timer;
    const bool saved = harness.engine.save_store(store.string()).succeeded();
    report(saved ? "save store (5000 sets, 20000 members)" : "save store failed", saved ? 1 : 0,
           save_timer.seconds());
    Timer load_timer;
    FabricEngine recovered;
    const bool loaded = recovered.load_store(store.string()).succeeded();
    report(loaded ? "load store (5000 sets, 20000 members)" : "load store failed", loaded ? 1 : 0,
           load_timer.seconds());
    std::error_code error;
    std::filesystem::remove(store, error);
    std::filesystem::remove(store.string() + ".bak", error);
  }

  std::cout << "benchmarks complete\n";
  return 0;
}
