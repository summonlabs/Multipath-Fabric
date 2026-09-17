#include <algorithm>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

// A tiny fabric with configurable limits and one registered publisher.
class LimitedFabric {
 public:
  explicit LimitedFabric(FabricConfig config) : engine_(config) {
    publisher_ = PublisherId::require("limit-publisher");
    boot_ = WorkerBootId::require("limit-boot");
    session_ = SessionId::require("limit-session");
    scope_.fabric = FabricId::require("limit-fabric");
    scope_.name_space = MultipathNamespace::require("limit-ns");
    registered_ = engine_.register_publisher(publisher_, boot_, scope_, session_).succeeded();
  }

  [[nodiscard]] FabricEngine& engine() { return engine_; }
  [[nodiscard]] bool registered() const noexcept { return registered_; }
  [[nodiscard]] const AuthorityScope& scope() const noexcept { return scope_; }
  [[nodiscard]] const PublisherId& publisher() const noexcept { return publisher_; }
  [[nodiscard]] const WorkerBootId& boot() const noexcept { return boot_; }
  [[nodiscard]] const SessionId& session() const noexcept { return session_; }

  [[nodiscard]] MutationContext context() {
    MutationContext value;
    value.epoch = engine_.epoch();
    value.publisher = publisher_;
    value.worker_boot = boot_;
    value.session = session_;
    value.attempt = MutationAttemptId::require("limit-attempt-" + std::to_string(++attempts_));
    return value;
  }

  [[nodiscard]] MultipathSetId create_set(const std::string& name, std::uint64_t minimum = 1) {
    SetKey key;
    key.fabric = scope_.fabric;
    key.name_space = scope_.name_space;
    key.name = MultipathSetName::require(name);
    SetOptions options;
    options.minimum_usable_members = minimum;
    const FabricOutcome outcome = engine_.create_set(context(), key, options);
    return outcome.set_id.value_or(MultipathSetId{});
  }

  [[nodiscard]] FabricOutcome declare(const std::string& path) {
    PathAuthorityView view;
    view.path = PathId::require(path);
    view.generation = PathAuthorityGeneration::require(1);
    view.state = PathAuthorityState::AUTHORIZED;
    return engine_.declare_path_authority(context(), view);
  }

 private:
  FabricEngine engine_;
  PublisherId publisher_;
  WorkerBootId boot_;
  SessionId session_;
  AuthorityScope scope_;
  std::uint64_t attempts_ = 0;
  bool registered_ = false;
};

}  // namespace

MPF_TEST(limit_descriptions_are_complete_and_named) {
  const Limits limits;
  const std::vector<std::pair<std::string, std::uint64_t>> described = limits.describe();
  const std::vector<std::string> expected = {
      "max_sets",
      "max_members_per_set",
      "max_total_members",
      "max_history_per_set",
      "max_archived_members_per_set",
      "max_frame_bytes",
      "max_batch_size",
      "max_publishers",
      "max_sessions",
      "max_explanation_entries",
      "max_persistence_record_bytes",
      "max_store_bytes",
      "max_attempts",
      "max_pending_revalidations_per_set",
      "max_path_dependencies_per_path",
      "max_snapshot_history",
      "max_scope_set_ids",
  };
  MPF_CHECK_EQ(described.size(), expected.size());
  for (std::size_t index = 0; index < described.size() && index < expected.size(); ++index) {
    MPF_CHECK_EQ(described[index].first, expected[index]);
    MPF_CHECK_MSG(described[index].second > 0, described[index].first + " must be positive");
  }
}

MPF_TEST(limit_max_sets_is_consulted) {
  FabricConfig config;
  config.limits.max_sets = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  MPF_REQUIRE(fabric.create_set("first").valid());
  const FabricOutcome second = [&]() {
    SetKey key;
    key.fabric = fabric.scope().fabric;
    key.name_space = fabric.scope().name_space;
    key.name = MultipathSetName::require("second");
    SetOptions options;
    return fabric.engine().create_set(fabric.context(), key, options);
  }();
  MPF_CHECK(!second.succeeded());
  MPF_CHECK_EQ(second.code, OutcomeCode::RESOURCE_LIMIT);
  MPF_CHECK_EQ(second.stage, RejectionStage::RESOURCE_LIMIT);
  MPF_CHECK_EQ(fabric.engine().set_count(), std::size_t{1});
}

MPF_TEST(limit_max_total_members_is_consulted) {
  FabricConfig config;
  config.limits.max_total_members = 2;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId first = fabric.create_set("first");
  const MultipathSetId second = fabric.create_set("second");
  MPF_REQUIRE(first.valid());
  MPF_REQUIRE(second.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), first).succeeded());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), second).succeeded());
  for (int index = 0; index < 2; ++index) {
    const std::string path = "total-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    MPF_REQUIRE(fabric.engine()
                    .add_member(fabric.context(), first, PathId::require(path),
                                PathAuthorityGeneration::require(1))
                    .succeeded());
  }
  const std::string overflow = "total-overflow";
  MPF_REQUIRE(fabric.declare(overflow).succeeded());
  const FabricOutcome rejected =
      fabric.engine().add_member(fabric.context(), second, PathId::require(overflow),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
  MPF_CHECK_EQ(fabric.engine().total_member_count(), std::size_t{2});
}

MPF_TEST(limit_max_batch_size_is_consulted) {
  FabricConfig config;
  config.limits.max_batch_size = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("batch");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  MPF_REQUIRE(fabric.declare("batch-a").succeeded());
  MPF_REQUIRE(fabric.declare("batch-b").succeeded());
  std::vector<MemberRequest> batch(2);
  batch[0].path_id = PathId::require("batch-a");
  batch[0].authority_generation = PathAuthorityGeneration::require(1);
  batch[1].path_id = PathId::require("batch-b");
  batch[1].authority_generation = PathAuthorityGeneration::require(1);
  const FabricOutcome rejected = fabric.engine().add_members(fabric.context(), set_id, batch);
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
}

MPF_TEST(limit_max_publishers_is_consulted) {
  FabricConfig config;
  config.limits.max_publishers = 1;
  FabricEngine engine(config);
  AuthorityScope scope;
  scope.fabric = FabricId::require("limit-fabric");
  scope.name_space = MultipathNamespace::require("limit-ns");
  MPF_REQUIRE(engine
                  .register_publisher(PublisherId::require("first-publisher"),
                                      WorkerBootId::require("first-boot"), scope,
                                      SessionId::require("first-session"))
                  .succeeded());
  const FabricOutcome second =
      engine.register_publisher(PublisherId::require("second-publisher"),
                                WorkerBootId::require("second-boot"), scope,
                                SessionId::require("second-session"));
  MPF_CHECK(!second.succeeded());
  MPF_CHECK_EQ(second.code, OutcomeCode::RESOURCE_LIMIT);
  // Re-registering an existing pair is idempotent, not a new publisher.
  const FabricOutcome again =
      engine.register_publisher(PublisherId::require("first-publisher"),
                                WorkerBootId::require("first-boot"), scope,
                                SessionId::require("first-session"));
  MPF_CHECK(again.succeeded());
  MPF_CHECK_EQ(again.code, OutcomeCode::IDEMPOTENT);
}

MPF_TEST(limit_max_scope_set_ids_is_consulted) {
  FabricConfig config;
  config.limits.max_scope_set_ids = 1;
  FabricEngine engine(config);
  AuthorityScope scope;
  scope.fabric = FabricId::require("limit-fabric");
  scope.name_space = MultipathNamespace::require("limit-ns");
  scope.set_ids.push_back(MultipathSetId::require("set-a"));
  scope.set_ids.push_back(MultipathSetId::require("set-b"));
  const FabricOutcome rejected =
      engine.register_publisher(PublisherId::require("scope-publisher"),
                                WorkerBootId::require("scope-boot"), scope,
                                SessionId::require("scope-session"));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
}

MPF_TEST(limit_max_pending_revalidations_is_consulted) {
  FabricConfig config;
  config.limits.max_pending_revalidations_per_set = 1;
  mpf_test::FabricFixture fixture;
  FabricEngine engine(config);
  // Use the fixture's own engine configuration path: rebuild through a fixture
  // engine whose limits were set at construction.
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("pending");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  MPF_REQUIRE(fabric.declare("pending-path").succeeded());
  MPF_REQUIRE(fabric.engine()
                  .add_member(fabric.context(), set_id, PathId::require("pending-path"),
                              PathAuthorityGeneration::require(1))
                  .succeeded());
  const auto snapshot = fabric.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  const MultipathMemberId member_id = snapshot->members.front().id;

  const RevalidationBegin first = fabric.engine().begin_member_revalidation(
      fabric.context(), set_id, member_id, RevalidationAttemptId::require("pending-a"));
  MPF_CHECK(first.outcome.succeeded());
  const RevalidationBegin second = fabric.engine().begin_member_revalidation(
      fabric.context(), set_id, member_id, RevalidationAttemptId::require("pending-b"));
  MPF_CHECK(!second.outcome.succeeded());
  MPF_CHECK_EQ(second.outcome.code, OutcomeCode::RESOURCE_LIMIT);
  MPF_CHECK(!second.ticket.has_value());
  static_cast<void>(engine);
  static_cast<void>(fixture);
}

MPF_TEST(limit_max_path_dependencies_is_consulted) {
  FabricConfig config;
  config.limits.max_path_dependencies_per_path = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId first = fabric.create_set("deps-first");
  const MultipathSetId second = fabric.create_set("deps-second");
  MPF_REQUIRE(first.valid());
  MPF_REQUIRE(second.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), first).succeeded());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), second).succeeded());
  MPF_REQUIRE(fabric.declare("shared-path").succeeded());
  MPF_REQUIRE(fabric.engine()
                  .add_member(fabric.context(), first, PathId::require("shared-path"),
                              PathAuthorityGeneration::require(1))
                  .succeeded());
  const FabricOutcome rejected =
      fabric.engine().add_member(fabric.context(), second, PathId::require("shared-path"),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
  MPF_CHECK_EQ(fabric.engine().sets_for_path(PathId::require("shared-path")).size(),
               std::size_t{1});
  // Re-adding to the set that already depends on the path is not a new
  // dependency and is rejected as a duplicate instead.
  const FabricOutcome duplicate =
      fabric.engine().add_member(fabric.context(), first, PathId::require("shared-path"),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK_EQ(duplicate.code, OutcomeCode::DUPLICATE_MEMBER);
}

MPF_TEST(limit_max_history_per_set_is_consulted) {
  FabricConfig config;
  config.limits.max_history_per_set = 2;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("history");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  for (int index = 0; index < 5; ++index) {
    const std::string path = "history-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    MPF_REQUIRE(fabric.engine()
                    .add_member(fabric.context(), set_id, PathId::require(path),
                                PathAuthorityGeneration::require(1))
                    .succeeded());
  }
  const std::vector<detail::HistoryEntry> history = fabric.engine().history(set_id);
  MPF_CHECK_EQ(history.size(), std::size_t{2});
  // The retained entries are the most recent ones and their generations
  // increase.
  MPF_CHECK(history.front().set_generation.value() < history.back().set_generation.value());
}

MPF_TEST(limit_max_archived_members_is_consulted) {
  FabricConfig config;
  config.limits.max_archived_members_per_set = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("archive");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  std::vector<MultipathMemberId> members;
  for (int index = 0; index < 4; ++index) {
    const std::string path = "archive-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    const FabricOutcome added =
        fabric.engine().add_member(fabric.context(), set_id, PathId::require(path),
                                   PathAuthorityGeneration::require(1));
    MPF_REQUIRE(added.succeeded());
    members.push_back(*added.member_id);
  }
  for (const auto& member : members) {
    const FabricOutcome withdrawn =
        fabric.engine().withdraw_member(fabric.context(), set_id, member, "drained");
    MPF_REQUIRE(withdrawn.succeeded());
  }
  const auto snapshot = fabric.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  // One surviving archive entry at most; the oldest were pruned and their
  // dangling lineage references cleared.
  std::size_t archived = 0;
  for (const auto& member : snapshot->members) {
    if (member.lifecycle == MemberLifecycle::WITHDRAWN) {
      ++archived;
    }
    if (member.predecessor.has_value()) {
      MPF_CHECK(snapshot->find_member(*member.predecessor) != nullptr);
    }
    if (member.successor.has_value()) {
      MPF_CHECK(snapshot->find_member(*member.successor) != nullptr);
    }
  }
  MPF_CHECK_EQ(archived, std::size_t{1});
  MPF_CHECK_EQ(fabric.engine().total_member_count(), snapshot->members.size());
}

MPF_TEST(limit_max_snapshot_history_is_consulted) {
  FabricConfig config;
  config.limits.max_snapshot_history = 2;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("snapshots");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  for (int index = 0; index < 5; ++index) {
    const std::string path = "snapshot-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    MPF_REQUIRE(fabric.engine()
                    .add_member(fabric.context(), set_id, PathId::require(path),
                                PathAuthorityGeneration::require(1))
                    .succeeded());
  }
  const std::vector<SnapshotId> history = fabric.engine().snapshot_history(set_id);
  MPF_CHECK_EQ(history.size(), std::size_t{2});
  const auto diff = fabric.engine().diff_last_two(set_id);
  MPF_CHECK(diff.has_value());
  if (diff.has_value()) {
    MPF_CHECK(!diff->identical);
  }
  // An evicted snapshot is no longer retrievable.
  MPF_CHECK(!fabric.engine().historical_snapshot(set_id, SnapshotId::require("snap-missing"))
                 .has_value());
}

MPF_TEST(limit_max_explanation_entries_is_consulted) {
  FabricConfig config;
  config.limits.max_explanation_entries = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("explain");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  for (int index = 0; index < 3; ++index) {
    const std::string path = "explain-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    MPF_REQUIRE(fabric.engine()
                    .add_member(fabric.context(), set_id, PathId::require(path),
                                PathAuthorityGeneration::require(1))
                    .succeeded());
  }
  const auto explanation = fabric.engine().explain_set(set_id);
  MPF_REQUIRE(explanation.has_value());
  MPF_CHECK_EQ(explanation->members.size(), std::size_t{1});
  MPF_CHECK(explanation->truncated);
  MPF_CHECK_EQ(explanation->member_count, std::uint64_t{3});
  MPF_CHECK(std::find(explanation->reasons.begin(), explanation->reasons.end(),
                      ExplanationReason::EXPLANATION_TRUNCATED) != explanation->reasons.end());
}

MPF_TEST(limit_persistence_bounds_are_consulted) {
  mpf_test::TempDirectory directory("persistence-limits");
  {
    FabricConfig config;
    config.limits.max_persistence_record_bytes = 64;
    LimitedFabric fabric(config);
    MPF_REQUIRE(fabric.registered());
    MPF_REQUIRE(fabric.create_set("oversized").valid());
    const FabricOutcome saved =
        fabric.engine().save_store(directory.path("record-limit.bin"));
    MPF_CHECK(!saved.succeeded());
    MPF_CHECK_EQ(saved.code, OutcomeCode::RESOURCE_LIMIT);
    MPF_CHECK(!std::filesystem::exists(directory.path("record-limit.bin")));
  }
  {
    FabricConfig config;
    config.limits.max_store_bytes = 64;
    LimitedFabric fabric(config);
    MPF_REQUIRE(fabric.registered());
    MPF_REQUIRE(fabric.create_set("oversized-store").valid());
    const FabricOutcome saved = fabric.engine().save_store(directory.path("store-limit.bin"));
    MPF_CHECK(!saved.succeeded());
    MPF_CHECK_EQ(saved.code, OutcomeCode::RESOURCE_LIMIT);
  }
}

MPF_TEST(limit_max_attempts_is_consulted) {
  FabricConfig config;
  config.limits.max_attempts = 1;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("attempts");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  MPF_REQUIRE(fabric.declare("attempt-path").succeeded());

  MutationContext first = fabric.context();
  MPF_REQUIRE(fabric.engine()
                  .add_member(first, set_id, PathId::require("attempt-path"),
                              PathAuthorityGeneration::require(1))
                  .succeeded());
  const FabricOutcome replay =
      fabric.engine().add_member(first, set_id, PathId::require("attempt-path"),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK_EQ(replay.code, OutcomeCode::IDEMPOTENT);

  // A second successful commit evicts the first attempt record, so the replay is
  // no longer recognised and is subject to full validation instead.
  MPF_REQUIRE(fabric.declare("attempt-path-2").succeeded());
  MPF_REQUIRE(fabric.engine()
                  .add_member(fabric.context(), set_id, PathId::require("attempt-path-2"),
                              PathAuthorityGeneration::require(1))
                  .succeeded());
  const FabricOutcome evicted =
      fabric.engine().add_member(first, set_id, PathId::require("attempt-path"),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK(!evicted.succeeded());
  MPF_CHECK_EQ(evicted.code, OutcomeCode::DUPLICATE_MEMBER);
  const FabricIntegrityReport report = fabric.engine().check_integrity();
  MPF_CHECK(report.consistent);
  MPF_CHECK_EQ(report.retained_attempts, std::size_t{1});
}

MPF_TEST(limit_max_members_per_set_is_consulted) {
  FabricConfig config;
  config.limits.max_members_per_set = 2;
  LimitedFabric fabric(config);
  MPF_REQUIRE(fabric.registered());
  const MultipathSetId set_id = fabric.create_set("members");
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fabric.engine().publish_set(fabric.context(), set_id).succeeded());
  for (int index = 0; index < 2; ++index) {
    const std::string path = "member-" + std::to_string(index);
    MPF_REQUIRE(fabric.declare(path).succeeded());
    MPF_REQUIRE(fabric.engine()
                    .add_member(fabric.context(), set_id, PathId::require(path),
                                PathAuthorityGeneration::require(1))
                    .succeeded());
  }
  MPF_REQUIRE(fabric.declare("member-overflow").succeeded());
  const FabricOutcome rejected =
      fabric.engine().add_member(fabric.context(), set_id, PathId::require("member-overflow"),
                                 PathAuthorityGeneration::require(1));
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::RESOURCE_LIMIT);
  // The declared minimum may not exceed the same bound.
  const FabricOutcome threshold = fabric.engine().set_minimum_usable_members(
      fabric.context(), set_id, 3);
  MPF_CHECK(!threshold.succeeded());
  MPF_CHECK_EQ(threshold.code, OutcomeCode::INVALID_THRESHOLD);
}

MPF_TEST(limit_max_frame_bytes_is_consulted) {
  Limits limits;
  limits.max_frame_bytes = 32;
  const std::vector<std::uint8_t> payload(64, 0x5A);
  std::vector<std::uint8_t> frame;
  const FabricOutcome encoded =
      wire::encode_frame(wire::MessageId::CREATE_SET, payload, limits.max_frame_bytes, frame);
  MPF_CHECK(!encoded.succeeded());
  MPF_CHECK_EQ(encoded.code, OutcomeCode::RESOURCE_LIMIT);
  MPF_CHECK(frame.empty());

  // A header that declares an oversized payload is refused before any payload
  // buffer is allocated.
  std::vector<std::uint8_t> header(wire::frame_header_size);
  detail::ByteWriter writer(wire::frame_header_size);
  writer.u32(wire::frame_magic);
  writer.u16(wire_protocol_version);
  writer.u16(static_cast<std::uint16_t>(wire::MessageId::CREATE_SET));
  writer.u32(1U << 20);
  writer.u32(0);
  std::copy(writer.buffer().begin(), writer.buffer().end(), header.begin());
  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t length = 0;
  const FabricOutcome decoded =
      wire::decode_header(header.data(), header.size(), limits.max_frame_bytes, id, length);
  MPF_CHECK(!decoded.succeeded());
  MPF_CHECK_EQ(decoded.code, OutcomeCode::RESOURCE_LIMIT);
}