// mpf_publisher -- a Multipath Fabric publisher/worker process.
//
// Connects to a coordinator, registers an authority scope, optionally
// bootstraps a set population, announces readiness and then stays alive until
// it is terminated or its lifetime expires. Used by the distributed proofs as a
// real, independently killable OS process.
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>

#include "tool_common.hpp"

int main(int argc, char** argv) {
  mpf_tool::Arguments arguments(argc, argv);
  if (arguments.has("--help")) {
    std::cout << "usage: mpf_publisher --port N [--host HOST] [--publisher ID] [--boot ID] "
                 "[--fabric F] [--namespace NS] [--sets N] [--members M] [--minimum K] "
                 "[--ready-file PATH] [--lifetime-ms N] [--no-publish]\n";
    return 0;
  }
  const std::string host = arguments.text("--host", "127.0.0.1");
  const std::uint64_t port = arguments.number("--port", 0);
  if (port == 0 || port > 65535) {
    std::cerr << "mpf_publisher requires --port N\n";
    return 2;
  }
  const std::string publisher_text = arguments.text("--publisher", "publisher-a");
  const std::string boot_text = arguments.text("--boot", "boot-a1");
  const std::string fabric_text = arguments.text("--fabric", "fabric-main");
  const std::string namespace_text = arguments.text("--namespace", "mp-ns");
  const std::uint64_t set_count = arguments.number("--sets", 1);
  const std::uint64_t member_count = arguments.number("--members", 3);
  const std::uint64_t minimum = arguments.number("--minimum", 1);
  const std::uint64_t generation = arguments.number("--generation", 1);
  const std::uint64_t lifetime_ms = arguments.number("--lifetime-ms", 0);
  const std::string ready_file = arguments.text("--ready-file", "");
  const bool publish = !arguments.has("--no-publish");

  const auto publisher = multipath_fabric::PublisherId::parse(publisher_text);
  const auto boot = multipath_fabric::WorkerBootId::parse(boot_text);
  const auto fabric = multipath_fabric::FabricId::parse(fabric_text);
  const auto name_space = multipath_fabric::MultipathNamespace::parse(namespace_text);
  if (!publisher.has_value() || !boot.has_value() || !fabric.has_value() ||
      !name_space.has_value()) {
    std::cerr << "publisher, boot, fabric and namespace must be valid identities\n";
    return 2;
  }

  multipath_fabric::MultipathFabricClient client;
  const multipath_fabric::FabricOutcome connected =
      client.connect(host, static_cast<std::uint16_t>(port));
  if (!connected.succeeded()) {
    std::cerr << "connect failed: " << connected.render() << '\n';
    return 3;
  }

  multipath_fabric::AuthorityScope scope;
  scope.fabric = *fabric;
  scope.name_space = *name_space;
  const multipath_fabric::FabricOutcome registered =
      client.register_publisher(*publisher, *boot, scope);
  std::cout << "REGISTER " << registered.render() << '\n';
  if (!registered.succeeded()) {
    return 4;
  }

  std::uint64_t attempt_counter = 0;
  const auto next_attempt = [&]() {
    return multipath_fabric::MutationAttemptId::require("at-" + std::to_string(++attempt_counter));
  };

  std::string announced;
  const auto path_authority_generation =
      multipath_fabric::PathAuthorityGeneration::from_value(generation);
  if (!path_authority_generation.has_value()) {
    std::cerr << "--generation must be at least 1\n";
    return 2;
  }

  for (std::uint64_t s = 0; s < set_count; ++s) {
    multipath_fabric::SetKey key;
    key.fabric = *fabric;
    key.name_space = *name_space;
    key.name = multipath_fabric::MultipathSetName::require("set" + std::to_string(s));
    multipath_fabric::SetOptions options;
    options.minimum_usable_members = minimum;
    multipath_fabric::MutationContext create_context;
    create_context.attempt = next_attempt();
    const multipath_fabric::FabricOutcome created =
        client.create_set(create_context, key, options);
    std::cout << "CREATE_SET " << key.render() << ' ' << created.render() << '\n';
    if (!created.succeeded() || !created.set_id.has_value()) {
      return 5;
    }
    if (publish) {
      multipath_fabric::MutationContext publish_context;
      publish_context.attempt = next_attempt();
      const multipath_fabric::FabricOutcome published =
          client.publish_set(publish_context, *created.set_id);
      std::cout << "PUBLISH " << created.set_id->view() << ' ' << published.render() << '\n';
      if (!published.succeeded()) {
        return 6;
      }
    }
    for (std::uint64_t m = 0; m < member_count; ++m) {
      const std::string path_text =
          fabric_text + "/p" + std::to_string(s) + "-" + std::to_string(m);
      const auto path = multipath_fabric::PathId::parse(path_text);
      if (!path.has_value()) {
        std::cerr << "generated path identity is invalid\n";
        return 7;
      }
      multipath_fabric::PathAuthorityView view;
      view.path = *path;
      view.generation = *path_authority_generation;
      view.state = multipath_fabric::PathAuthorityState::AUTHORIZED;
      multipath_fabric::MutationContext declare_context;
      declare_context.attempt = next_attempt();
      const multipath_fabric::FabricOutcome declared =
          client.declare_path_authority(declare_context, view);
      if (!declared.succeeded()) {
        std::cout << "DECLARE " << path->view() << ' ' << declared.render() << '\n';
        return 8;
      }
      multipath_fabric::MutationContext add_context;
      add_context.attempt = next_attempt();
      const multipath_fabric::FabricOutcome added = client.add_member(
          add_context, *created.set_id, *path, *path_authority_generation);
      std::cout << "ADD_MEMBER " << path->view() << ' ' << added.render() << '\n';
      if (!added.succeeded()) {
        return 9;
      }
    }
    announced += created.set_id->str();
    announced += ' ';
  }

  std::cout << "READY sets=" << set_count << " members=" << member_count << '\n';
  std::cout.flush();
  if (!ready_file.empty() && !mpf_tool::write_announcement(
                                 ready_file, "READY " + std::to_string(set_count) + " " +
                                                 announced + "\n")) {
    std::cerr << "cannot write readiness announcement to " << ready_file << '\n';
    return 10;
  }

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(lifetime_ms == 0 ? 3600000 : lifetime_ms);
  while (lifetime_ms == 0 ? true : std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  std::cout << "DONE\n";
  return 0;
}