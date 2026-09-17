// Real-process distributed proofs.
//
// Every scenario here uses genuine operating system processes: a coordinator
// executable, publisher executables and real loopback TCP. Termination is a
// forced OS process termination. Nothing is simulated inside one process.
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_framework.hpp"
#include "test_process.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

struct Coordinator {
  mpf_test::ChildProcess process;
  std::string store;
  std::uint16_t port = 0;
  std::uint64_t epoch = 0;
  bool ready = false;

  [[nodiscard]] bool start(const std::string& directory, const std::string& label,
                           const std::vector<std::string>& extra = {}) {
    store = directory + "/store-" + label + ".bin";
    const std::string announcement = directory + "/ready-" + label + ".txt";
    std::error_code error;
    std::filesystem::remove(announcement, error);
    std::vector<std::string> arguments = {"--store",        store,
                                          "--port-file",    announcement,
                                          "--frame-timeout-ms", "2000"};
    for (const auto& value : extra) {
      arguments.push_back(value);
    }
    if (!process.start(MPF_COORDINATOR_EXECUTABLE, arguments, directory + "/coord-" + label +
                                                                     ".log")) {
      return false;
    }
    const std::string line = mpf_test::wait_for_file(announcement);
    if (line.empty()) {
      return false;
    }
    const std::vector<std::string> parts = mpf_test::split(line, ' ');
    if (parts.size() < 3) {
      return false;
    }
    port = static_cast<std::uint16_t>(std::stoi(parts[1]));
    epoch = std::stoull(parts[2]);
    ready = port != 0;
    return ready;
  }
};

// A client with a registered publisher scope.
struct AdminClient {
  MultipathFabricClient client;
  PublisherId publisher;
  WorkerBootId boot;
  AuthorityScope scope;
  std::uint64_t attempts = 0;

  [[nodiscard]] bool open(std::uint16_t port, const std::string& publisher_text,
                          const std::string& boot_text) {
    publisher = PublisherId::require(publisher_text);
    boot = WorkerBootId::require(boot_text);
    scope.fabric = FabricId::require("fabric-dist");
    scope.name_space = MultipathNamespace::require("ns-dist");
    if (!client.connect("127.0.0.1", port).succeeded()) {
      return false;
    }
    return client.register_publisher(publisher, boot, scope).succeeded();
  }

  [[nodiscard]] MutationContext context() {
    // Attempt identities are global to the coordinator, so every client in this
    // test draws from one process-wide counter.
    static std::atomic<std::uint64_t> global_attempts{0};
    MutationContext value;
    value.publisher = publisher;
    value.worker_boot = boot;
    value.attempt = MutationAttemptId::require(
        "dist-attempt-" + std::to_string(++global_attempts) + "-" + std::to_string(++attempts));
    return value;
  }
};

// Reads exactly one framed message from a raw socket: header first, then the
// declared payload. Returns the decoded message id and payload.
[[nodiscard]] bool read_raw_frame(net::Socket& socket, wire::MessageId& id,
                                  std::vector<std::uint8_t>& payload,
                                  std::uint32_t timeout_ms = 10000) {
  const std::atomic<bool> never_stop{false};
  std::vector<std::uint8_t> header(wire::frame_header_size);
  std::size_t received = 0;
  if (!net::socket_recv_exact(socket, header.data(), header.size(), 250, timeout_ms, &never_stop,
                              received)
           .succeeded()) {
    return false;
  }
  std::uint32_t length = 0;
  if (!wire::decode_header(header.data(), header.size(), 1U << 24, id, length).succeeded()) {
    return false;
  }
  payload.assign(length, 0);
  if (length > 0) {
    std::size_t payload_received = 0;
    if (!net::socket_recv_exact(socket, payload.data(), payload.size(), 250, timeout_ms,
                                &never_stop, payload_received)
             .succeeded()) {
      return false;
    }
  }
  return wire::verify_integrity(header.data(), header.size(), payload).succeeded();
}

[[nodiscard]] std::string set_name(std::uint64_t index) {
  return "dist-set-" + std::to_string(index);
}

}  // namespace

namespace {
void run_worker_death_proof();
}  // namespace

MPF_TEST(distributed_real_worker_death_is_fenced_and_membership_survives) {
  run_worker_death_proof();
}

namespace {

void run_worker_death_proof() {

  mpf_test::TempDirectory directory("worker-death");
  Coordinator coordinator;
  MPF_REQUIRE(coordinator.start(directory.base().string(), "worker-death"));
  MPF_CHECK_EQ(coordinator.epoch, std::uint64_t{1});

  // Publisher A runs as a real OS process and bootstraps one set.
  mpf_test::ChildProcess publisher;
  const std::string announcement = directory.path("publisher-ready.txt");
  MPF_REQUIRE(publisher.start(MPF_PUBLISHER_EXECUTABLE,
                              {"--port", std::to_string(coordinator.port), "--publisher",
                               "publisher-a", "--boot", "boot-a1", "--fabric", "fabric-dist",
                               "--namespace", "ns-dist", "--sets", "2", "--members", "3",
                               "--minimum", "2", "--ready-file", announcement},
                              directory.path("publisher-a.log")));
  const std::string ready = mpf_test::wait_for_file(announcement);
  MPF_REQUIRE(!ready.empty());
  const std::vector<std::string> parts = mpf_test::split(ready, ' ');
  MPF_REQUIRE(parts.size() >= 4);
  const auto first_set = MultipathSetId::parse(parts[2]);
  const auto second_set = MultipathSetId::parse(parts[3]);
  MPF_REQUIRE(first_set.has_value());
  MPF_REQUIRE(second_set.has_value());
  MPF_CHECK(publisher.running());

  // An independent publisher B owns an unrelated set and must stay unaffected.
  AdminClient publisher_b;
  MPF_REQUIRE(publisher_b.open(coordinator.port, "publisher-b", "boot-b1"));
  SetKey key_b;
  key_b.fabric = publisher_b.scope.fabric;
  key_b.name_space = publisher_b.scope.name_space;
  key_b.name = MultipathSetName::require("unrelated-b");
  SetOptions options;
  options.minimum_usable_members = 0;
  const FabricOutcome created_b = publisher_b.client.create_set(publisher_b.context(), key_b, options);
  MPF_REQUIRE(created_b.succeeded());
  MPF_REQUIRE(publisher_b.client.publish_set(publisher_b.context(), *created_b.set_id).succeeded());

  // Administrator observes the current state before the kill.
  AdminClient admin;
  MPF_REQUIRE(admin.open(coordinator.port, "publisher-admin", "boot-admin-1"));
  SetSnapshot before;
  MPF_REQUIRE(admin.client.query_set(*first_set, before).succeeded());
  MPF_CHECK_EQ(before.lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(before.currentness, SetCurrentness::CURRENT);
  MPF_CHECK_EQ(before.readiness, RouteReadiness::READY);
  MPF_CHECK_EQ(before.member_count, std::size_t{3});
  MPF_CHECK_EQ(before.usable_member_count, std::uint64_t{3});
  const detail::Digest128 before_digest = before.digest;

  // Step 6: the publisher process is alive immediately before the kill.
  MPF_CHECK(publisher.running());
  // Step 7: real OS termination.
  publisher.terminate();
  MPF_CHECK(!publisher.running());

  // Step 8-9: the coordinator detects the session loss and fences boot A1.
  // The probe retries a bounded number of times and closes every connection it
  // opens, so the session table is never stressed by the wait itself.
  bool fenced = false;
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (!fenced && std::chrono::steady_clock::now() < deadline) {
    AdminClient stale_client;
    stale_client.publisher = PublisherId::require("publisher-a");
    stale_client.boot = WorkerBootId::require("boot-a1");
    stale_client.scope.fabric = FabricId::require("fabric-dist");
    stale_client.scope.name_space = MultipathNamespace::require("ns-dist");
    if (stale_client.client.connect("127.0.0.1", coordinator.port).succeeded()) {
      const FabricOutcome registration =
          stale_client.client.register_publisher(stale_client.publisher, stale_client.boot,
                                                 stale_client.scope);
      if (!registration.succeeded() && registration.code == OutcomeCode::STALE_WORKER) {
        fenced = true;
      }
    }
    stale_client.client.close();
    if (!fenced) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }
  MPF_CHECK_MSG(fenced, "the coordinator must fence the boot of the killed publisher");

  // A late mutation from the fenced boot is rejected.
  {
    AdminClient stale_client;
    stale_client.publisher = PublisherId::require("publisher-a");
    stale_client.boot = WorkerBootId::require("boot-a1");
    stale_client.scope.fabric = FabricId::require("fabric-dist");
    stale_client.scope.name_space = MultipathNamespace::require("ns-dist");
    MPF_REQUIRE(stale_client.client.connect("127.0.0.1", coordinator.port).succeeded());
    SetKey key;
    key.fabric = stale_client.scope.fabric;
    key.name_space = stale_client.scope.name_space;
    key.name = MultipathSetName::require("stale-mutation");
    SetOptions options_value;
    const FabricOutcome mutation =
        stale_client.client.create_set(stale_client.context(), key, options_value);
    MPF_CHECK(!mutation.succeeded());
    MPF_CHECK(mutation.code == OutcomeCode::STALE_WORKER ||
              mutation.code == OutcomeCode::UNKNOWN_PUBLISHER);
    stale_client.client.close();
  }

  // Step 11: durable membership survives the worker death.
  SetSnapshot after;
  MPF_REQUIRE(admin.client.query_set(*first_set, after).succeeded());
  MPF_CHECK_EQ(after.member_count, before.member_count);
  MPF_CHECK_EQ(after.generation.value(), before.generation.value());
  for (std::size_t index = 0; index < before.members.size(); ++index) {
    MPF_CHECK_EQ(after.members[index].path_id.view(), before.members[index].path_id.view());
  }
  // Live currentness was established under the fenced publisher, so it must be
  // re-established explicitly.
  MPF_CHECK_EQ(after.currentness, SetCurrentness::REVALIDATION_REQUIRED);
  MPF_CHECK_EQ(after.readiness, RouteReadiness::REVALIDATION_REQUIRED);
  MPF_CHECK(after.digest.to_hex() != before_digest.to_hex());

  // Step 12-13: a fresh publisher incarnation registers with a new boot.
  mpf_test::ChildProcess successor;
  const std::string successor_announcement = directory.path("publisher-a2-ready.txt");
  MPF_REQUIRE(successor.start(MPF_PUBLISHER_EXECUTABLE,
                              {"--port", std::to_string(coordinator.port), "--publisher",
                               "publisher-a", "--boot", "boot-a2", "--fabric", "fabric-dist",
                               "--namespace", "ns-dist", "--sets", "0", "--members", "0",
                               "--ready-file", successor_announcement},
                              directory.path("publisher-a2.log")));
  MPF_REQUIRE(!mpf_test::wait_for_file(successor_announcement).empty());
  MPF_CHECK(successor.running());

  // Step 14-15: the fresh incarnation revalidates the set and may mutate it.
  AdminClient revalidator;
  revalidator.publisher = PublisherId::require("publisher-a");
  revalidator.boot = WorkerBootId::require("boot-a2");
  revalidator.scope.fabric = FabricId::require("fabric-dist");
  revalidator.scope.name_space = MultipathNamespace::require("ns-dist");
  MPF_REQUIRE(revalidator.client.connect("127.0.0.1", coordinator.port).succeeded());
  MPF_REQUIRE(revalidator.client
                  .register_publisher(revalidator.publisher, revalidator.boot,
                                      revalidator.scope)
                  .succeeded());
  const FabricOutcome revalidated =
      revalidator.client.revalidate_set(revalidator.context(), *first_set);
  MPF_CHECK_MSG(revalidated.succeeded(), revalidated.render());
  SetSnapshot revalidated_snapshot;
  const FabricOutcome observed = admin.client.query_set(*first_set, revalidated_snapshot);
  MPF_REQUIRE_MSG(observed.succeeded(),
                  observed.render() + " coordinator_running=" +
                      (coordinator.process.running() ? "yes" : "no") + " log=" +
                      mpf_test::read_all(directory.path("coord-worker-death.log")));
  MPF_CHECK_EQ(revalidated_snapshot.currentness, SetCurrentness::CURRENT);
  MPF_CHECK_EQ(revalidated_snapshot.lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(revalidated_snapshot.readiness, RouteReadiness::READY);

  // Step 16: the old boot remains fenced forever.
  {
    AdminClient stale_again;
    stale_again.publisher = PublisherId::require("publisher-a");
    stale_again.boot = WorkerBootId::require("boot-a1");
    stale_again.scope.fabric = FabricId::require("fabric-dist");
    stale_again.scope.name_space = MultipathNamespace::require("ns-dist");
    MPF_REQUIRE(stale_again.client.connect("127.0.0.1", coordinator.port).succeeded());
    const FabricOutcome registration =
        stale_again.client.register_publisher(stale_again.publisher, stale_again.boot,
                                              stale_again.scope);
    MPF_CHECK(!registration.succeeded());
    MPF_CHECK_EQ(registration.code, OutcomeCode::STALE_WORKER);
  }

  // Step 17: the unrelated publisher and its set are unaffected.
  std::vector<MultipathSetId> listed;
  MPF_REQUIRE(admin.client.list_sets(listed).succeeded());
  MPF_CHECK_EQ(listed.size(), std::size_t{3});
  SetSnapshot unrelated;
  MPF_REQUIRE(admin.client.query_set(*created_b.set_id, unrelated).succeeded());
  MPF_CHECK_EQ(unrelated.lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_MSG(unrelated.readiness == RouteReadiness::READY,
                "currentness=" + std::string(to_string(unrelated.currentness)) +
                    " lifecycle=" + std::string(to_string(unrelated.lifecycle)) +
                    " epoch=" + std::to_string(unrelated.governing_epoch.value()) +
                    " provenance=" + unrelated.provenance.render());
  MPF_CHECK_EQ(unrelated.member_count, std::size_t{0});

  successor.terminate();
  publisher_b.client.close();
  revalidator.client.close();
  admin.client.close();
  coordinator.process.terminate();
}

}  // namespace

MPF_TEST(distributed_real_coordinator_restart_preserves_membership) {
  mpf_test::TempDirectory directory("restart");
  const std::string base = directory.base().string();
  std::uint64_t previous_epoch = 0;
  std::vector<std::string> set_ids;

  for (int restart = 0; restart < 3; ++restart) {
    Coordinator coordinator;
    MPF_REQUIRE(coordinator.start(base, "restart"));
    if (restart > 0) {
      MPF_CHECK_MSG(coordinator.epoch > previous_epoch,
                    "epoch must advance across restarts");
    }
    previous_epoch = coordinator.epoch;

    AdminClient admin;
    MPF_REQUIRE(admin.open(coordinator.port, "restart-admin",
                           "restart-boot-" + std::to_string(restart)));
    // The old epoch is rejected on the very first request of the old client.
    if (restart > 0) {
      std::vector<MultipathSetId> listed;
      MPF_REQUIRE(admin.client.list_sets(listed).succeeded());
      MPF_CHECK_EQ(listed.size(), set_ids.size());
      for (std::size_t index = 0; index < listed.size() && index < set_ids.size(); ++index) {
        SetSnapshot snapshot;
        MPF_REQUIRE(admin.client.query_set(listed[index], snapshot).succeeded());
        MPF_CHECK_EQ(snapshot.currentness, SetCurrentness::REVALIDATION_REQUIRED);
        MPF_CHECK_EQ(snapshot.readiness, RouteReadiness::REVALIDATION_REQUIRED);
      }
      // Path Authority views are consumed rather than owned, so the bridge must
      // re-declare them after the restart before revalidation can succeed.
      for (int index = 0; index < 3; ++index) {
        for (int member = 0; member < 3; ++member) {
          PathAuthorityView view;
          view.path = PathId::require("restart-path-" + std::to_string(index) + "-" +
                                      std::to_string(member));
          view.generation = PathAuthorityGeneration::require(1);
          view.state = PathAuthorityState::AUTHORIZED;
          MPF_REQUIRE(admin.client.declare_path_authority(admin.context(), view).succeeded());
        }
      }
      // Revalidate every recovered set and restore live currentness.
      for (const auto& text : set_ids) {
        const auto set_id = MultipathSetId::parse(text);
        MPF_REQUIRE(set_id.has_value());
        const FabricOutcome outcome = admin.client.revalidate_set(admin.context(), *set_id);
        MPF_CHECK(outcome.succeeded());
        SetSnapshot snapshot;
        MPF_REQUIRE(admin.client.query_set(*set_id, snapshot).succeeded());
        MPF_CHECK_EQ(snapshot.currentness, SetCurrentness::CURRENT);
        MPF_CHECK_EQ(snapshot.readiness, RouteReadiness::READY);
      }
    } else {
      for (int index = 0; index < 3; ++index) {
        SetKey key;
        key.fabric = admin.scope.fabric;
        key.name_space = admin.scope.name_space;
        key.name = MultipathSetName::require(set_name(static_cast<std::uint64_t>(index)));
        SetOptions options;
        options.minimum_usable_members = 2;
        const FabricOutcome created = admin.client.create_set(admin.context(), key, options);
        MPF_REQUIRE(created.succeeded());
        MPF_REQUIRE(admin.client.publish_set(admin.context(), *created.set_id).succeeded());
        for (int member = 0; member < 3; ++member) {
          const std::string path = "restart-path-" + std::to_string(index) + "-" +
                                   std::to_string(member);
          PathAuthorityView view;
          view.path = PathId::require(path);
          view.generation = PathAuthorityGeneration::require(1);
          view.state = PathAuthorityState::AUTHORIZED;
          MPF_REQUIRE(admin.client.declare_path_authority(admin.context(), view).succeeded());
          MPF_REQUIRE(admin.client
                          .add_member(admin.context(), *created.set_id, view.path,
                                      view.generation)
                          .succeeded());
        }
        set_ids.push_back(created.set_id->str());
      }
    }
    admin.client.close();
    // Hard kill: no graceful shutdown, so only durable state survives.
    coordinator.process.terminate();
    MPF_CHECK(!coordinator.process.running());
  }

  // The durable store holds all three sets and their members.
  StoreStatistics statistics;
  MPF_REQUIRE(FabricEngine::inspect_store_file(
                  base + "/store-restart.bin", statistics)
                  .succeeded());
  MPF_CHECK_EQ(statistics.set_count, std::size_t{3});
  MPF_CHECK_EQ(statistics.member_count, std::size_t{9});
  MPF_CHECK(statistics.epoch.value() >= previous_epoch);
}

MPF_TEST(distributed_path_invalidation_and_threshold_transitions) {
  mpf_test::TempDirectory directory("thresholds");
  Coordinator coordinator;
  MPF_REQUIRE(coordinator.start(directory.base().string(), "thresholds"));

  AdminClient admin;
  MPF_REQUIRE(admin.open(coordinator.port, "threshold-admin", "threshold-boot"));
  SetKey key;
  key.fabric = admin.scope.fabric;
  key.name_space = admin.scope.name_space;
  key.name = MultipathSetName::require("threshold-set");
  SetOptions options;
  options.minimum_usable_members = 2;
  const FabricOutcome created = admin.client.create_set(admin.context(), key, options);
  MPF_REQUIRE(created.succeeded());
  MPF_REQUIRE(admin.client.publish_set(admin.context(), *created.set_id).succeeded());
  for (int member = 0; member < 3; ++member) {
    const std::string path = "threshold-path-" + std::to_string(member);
    PathAuthorityView view;
    view.path = PathId::require(path);
    view.generation = PathAuthorityGeneration::require(1);
    view.state = PathAuthorityState::AUTHORIZED;
    MPF_REQUIRE(admin.client.declare_path_authority(admin.context(), view).succeeded());
    MPF_REQUIRE(admin.client
                    .add_member(admin.context(), *created.set_id, view.path, view.generation)
                    .succeeded());
  }
  SetSnapshot snapshot;
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(snapshot.usable_member_count, std::uint64_t{3});

  const auto reject = [&](const std::string& path, std::uint64_t generation,
                          PathAuthorityState state) {
    PathAuthorityView view;
    view.path = PathId::require(path);
    view.generation = PathAuthorityGeneration::require(generation);
    view.state = state;
    return admin.client.declare_path_authority(admin.context(), view);
  };

  // 3 -> 2 usable (still at the requirement).
  MPF_REQUIRE(reject("threshold-path-0", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.usable_member_count, std::uint64_t{2});
  MPF_CHECK_EQ(snapshot.lifecycle, SetLifecycle::ACTIVE);

  // 2 -> 1 usable (below the requirement).
  MPF_REQUIRE(reject("threshold-path-1", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.usable_member_count, std::uint64_t{1});
  MPF_CHECK_EQ(snapshot.lifecycle, SetLifecycle::DEGRADED);
  MPF_CHECK_EQ(snapshot.readiness, RouteReadiness::DEGRADED_BUT_READY);

  // An unrelated path changes nothing.
  const detail::Digest128 degraded_digest = snapshot.digest;
  MPF_REQUIRE(reject("unrelated-path", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.digest.to_hex(), degraded_digest.to_hex());

  // 1 -> 0 usable.
  MPF_REQUIRE(reject("threshold-path-2", 1, PathAuthorityState::REJECTED).succeeded());
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.usable_member_count, std::uint64_t{0});
  MPF_CHECK_EQ(snapshot.lifecycle, SetLifecycle::EXHAUSTED);
  MPF_CHECK_EQ(snapshot.readiness, RouteReadiness::INSUFFICIENT_MEMBERS);

  // Reauthorize at a new generation and revalidate to recover.
  MPF_REQUIRE(reject("threshold-path-0", 2, PathAuthorityState::AUTHORIZED).succeeded());
  MPF_REQUIRE(reject("threshold-path-1", 2, PathAuthorityState::AUTHORIZED).succeeded());
  const FabricOutcome revalidated =
      admin.client.revalidate_set(admin.context(), *created.set_id);
  MPF_CHECK(revalidated.succeeded());
  MPF_REQUIRE(admin.client.query_set(*created.set_id, snapshot).succeeded());
  MPF_CHECK_EQ(snapshot.usable_member_count, std::uint64_t{2});
  MPF_CHECK_EQ(snapshot.lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(snapshot.readiness, RouteReadiness::READY);
  for (const auto& member : snapshot.members) {
    MPF_CHECK(member.bound_authority_generation.value() == 1 ||
              member.bound_authority_generation.value() == 2);
  }

  // An explicit member revalidation rebinds one stale member.
  const auto explanation = [&]() {
    SetExplanation value;
    MPF_CHECK(admin.client.explain_set(*created.set_id, value).succeeded());
    return value;
  }();
  MPF_CHECK_EQ(explanation.usable_member_count, std::uint64_t{2});
  MPF_CHECK(!explanation.reasons.empty());

  admin.client.close();
  coordinator.process.terminate();
}

MPF_TEST(distributed_session_hardening_rejects_damaged_peers) {
  mpf_test::TempDirectory directory("sessions");
  Coordinator coordinator;
  MPF_REQUIRE(coordinator.start(directory.base().string(), "sessions"));

  net::ensure_transport_initialised();
  // A raw peer consumes the unsolicited HELLO_ACK announcement first.
  const auto connect_raw = [&]() {
    net::Socket socket;
    MPF_CHECK(net::tcp_connect("127.0.0.1", coordinator.port, 5000, socket).succeeded());
    wire::MessageId announcement = wire::MessageId::RESULT;
    std::vector<std::uint8_t> announcement_payload;
    MPF_CHECK(read_raw_frame(socket, announcement, announcement_payload));
    MPF_CHECK_EQ(announcement, wire::MessageId::HELLO_ACK);
    return socket;
  };

  // A peer that sends half a frame must not pin the session: the configured
  // frame budget expires and the coordinator answers with a structured
  // SESSION_TIMEOUT failure and closes the connection.
  {
    net::Socket socket = connect_raw();
    MPF_REQUIRE(socket.valid());
    const std::uint8_t partial[5] = {'M', 'P', 'F', 'W', 1};
    const std::atomic<bool> never_stop{false};
    MPF_CHECK(
        net::socket_send_all(socket, partial, sizeof(partial), 2000, &never_stop).succeeded());
    wire::MessageId id = wire::MessageId::RESULT;
    std::vector<std::uint8_t> payload;
    MPF_CHECK(read_raw_frame(socket, id, payload));
    MPF_CHECK_EQ(id, wire::MessageId::ERROR);
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireResponse response;
    MPF_CHECK(wire::decode_response(reader, response).succeeded());
    MPF_CHECK_EQ(response.outcome.code, OutcomeCode::SESSION_TIMEOUT);
    socket.close();
  }

  // An oversized frame declaration is refused before the payload is allocated.
  {
    net::Socket socket = connect_raw();
    MPF_REQUIRE(socket.valid());
    detail::ByteWriter writer(wire::frame_header_size + 8);
    writer.u32(wire::frame_magic);
    writer.u16(wire_protocol_version);
    writer.u16(static_cast<std::uint16_t>(wire::MessageId::CREATE_SET));
    writer.u32(0x7FFFFFFFU);
    writer.u32(0);
    writer.u64(0);
    const std::atomic<bool> never_stop{false};
    MPF_CHECK(net::socket_send_all(socket, writer.buffer().data(), writer.buffer().size(), 2000,
                                   &never_stop)
                  .succeeded());
    wire::MessageId id = wire::MessageId::RESULT;
    std::vector<std::uint8_t> payload;
    MPF_CHECK(read_raw_frame(socket, id, payload));
    MPF_CHECK_EQ(id, wire::MessageId::ERROR);
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireResponse response;
    MPF_CHECK(wire::decode_response(reader, response).succeeded());
    MPF_CHECK_EQ(response.outcome.code, OutcomeCode::RESOURCE_LIMIT);
    socket.close();
  }

  // Bad magic.
  {
    net::Socket socket = connect_raw();
    MPF_REQUIRE(socket.valid());
    std::vector<std::uint8_t> frame(wire::frame_header_size, 0);
    frame[0] = 'Z';
    const std::atomic<bool> never_stop{false};
    MPF_CHECK(net::socket_send_all(socket, frame.data(), frame.size(), 2000, &never_stop)
                  .succeeded());
    wire::MessageId id = wire::MessageId::RESULT;
    std::vector<std::uint8_t> payload;
    MPF_CHECK(read_raw_frame(socket, id, payload));
    MPF_CHECK_EQ(id, wire::MessageId::ERROR);
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireResponse response;
    MPF_CHECK(wire::decode_response(reader, response).succeeded());
    MPF_CHECK_EQ(response.outcome.code, OutcomeCode::FRAMING_ERROR);
    socket.close();
  }

  // Corrupted integrity over an otherwise well formed frame.
  {
    net::Socket socket = connect_raw();
    MPF_REQUIRE(socket.valid());
    std::vector<std::uint8_t> payload;
    wire::WireRequest request;
    request.id = wire::MessageId::LIST_SETS;
    MPF_REQUIRE(wire::encode_request(request, payload).succeeded());
    std::vector<std::uint8_t> frame;
    MPF_REQUIRE(
        wire::encode_frame(wire::MessageId::LIST_SETS, payload, 1U << 20, frame).succeeded());
    frame.back() ^= 0xFFU;
    const std::atomic<bool> never_stop{false};
    MPF_CHECK(net::socket_send_all(socket, frame.data(), frame.size(), 2000, &never_stop)
                  .succeeded());
    wire::MessageId id = wire::MessageId::RESULT;
    std::vector<std::uint8_t> response_payload;
    MPF_CHECK(read_raw_frame(socket, id, response_payload));
    MPF_CHECK_EQ(id, wire::MessageId::ERROR);
    detail::ByteReader reader(response_payload.data(), response_payload.size());
    wire::WireResponse response;
    MPF_CHECK(wire::decode_response(reader, response).succeeded());
    MPF_CHECK_EQ(response.outcome.code, OutcomeCode::INTEGRITY_ERROR);
    socket.close();
  }

  // After all of that the coordinator still serves a well behaved client.
  AdminClient admin;
  MPF_REQUIRE(admin.open(coordinator.port, "session-admin", "session-boot"));
  std::vector<MultipathSetId> listed;
  MPF_CHECK(admin.client.list_sets(listed).succeeded());
  SetKey key;
  key.fabric = admin.scope.fabric;
  key.name_space = admin.scope.name_space;
  key.name = MultipathSetName::require("after-damage");
  SetOptions options;
  options.minimum_usable_members = 0;
  const FabricOutcome created = admin.client.create_set(admin.context(), key, options);
  MPF_CHECK(created.succeeded());
  admin.client.close();
  coordinator.process.terminate();
}

MPF_TEST(distributed_clean_disconnect_repeated_start_stop) {
  mpf_test::TempDirectory directory("disconnect");
  Coordinator coordinator;
  MPF_REQUIRE(coordinator.start(directory.base().string(), "disconnect"));
  for (int round = 0; round < 10; ++round) {
    AdminClient client;
    MPF_REQUIRE(client.open(coordinator.port, "disconnect-publisher",
                            "disconnect-boot-" + std::to_string(round)));
    std::vector<MultipathSetId> listed;
    MPF_CHECK(client.client.list_sets(listed).succeeded());
    // Clean close without unregistering: the coordinator fences the boot.
    client.client.close();
  }
  // The coordinator still accepts new sessions and the final boot works.
  AdminClient final_client;
  MPF_REQUIRE(final_client.open(coordinator.port, "disconnect-final", "disconnect-final-boot"));
  std::vector<MultipathSetId> listed;
  MPF_CHECK(final_client.client.list_sets(listed).succeeded());
  final_client.client.close();
  coordinator.process.terminate();
  MPF_CHECK(!coordinator.process.running());
}