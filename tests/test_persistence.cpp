#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

// Independent re-implementation of the documented store layout. Building bytes
// here rather than through the library means the corruption cases exercise the
// decoder against a second, hand-written encoder.
class StoreBuilder {
 public:
  StoreBuilder() : writer_(1U << 20) { writer_.u32(persistence_format_version); }

  void epoch(std::uint64_t value) { writer_.u64(value); }
  void authority_generation(std::uint64_t value) { writer_.u64(value); }
  void fence_count(std::uint32_t value) { writer_.u32(value); }
  void set_count(std::uint32_t value) { writer_.u32(value); }

  void fence(const std::string& publisher, const std::string& boot, std::uint64_t epoch_value,
             const std::string& cause) {
    writer_.string(publisher, 128);
    writer_.string(boot, 128);
    writer_.u64(epoch_value);
    writer_.string(cause, 64);
  }

  void begin_set(const std::string& set_id, const std::string& fabric,
                 const std::string& name_space, const std::string& name,
                 std::uint64_t generation, std::uint64_t membership_generation,
                 std::uint64_t authority_generation_value, std::uint8_t lifecycle,
                 std::uint8_t currentness, bool admin_enabled, std::uint64_t minimum,
                 bool conditional, std::uint64_t governing_epoch) {
    writer_.string(set_id, 128);
    writer_.string(fabric, 128);
    writer_.string(name_space, 128);
    writer_.string(name, 128);
    writer_.u64(generation);
    writer_.u64(membership_generation);
    writer_.u64(authority_generation_value);
    writer_.u8(lifecycle);
    writer_.u8(currentness);
    writer_.boolean(admin_enabled);
    writer_.u64(minimum);
    writer_.boolean(conditional);
    writer_.u64(governing_epoch);
    writer_.boolean(false);  // no superseded_by
    writer_.boolean(false);  // no supersedes
    writer_.boolean(false);  // no revocation
    writer_.string("", 512);
    provenance();
  }

  void member_count(std::uint32_t value) { writer_.u32(value); }

  void member(const std::string& member_id, const std::string& path,
              std::uint64_t bound_generation, std::uint64_t member_generation,
              std::uint8_t lifecycle, std::uint8_t currentness, bool admin_enabled) {
    writer_.string(member_id, 128);
    writer_.string(path, 128);
    writer_.u64(bound_generation);
    writer_.u64(member_generation);
    writer_.u8(lifecycle);
    writer_.u8(currentness);
    writer_.boolean(admin_enabled);
    writer_.u64(0);
    writer_.u32(0);
    writer_.boolean(false);  // no predecessor
    writer_.boolean(false);  // no successor
    writer_.boolean(false);  // no Path Authority observation
    provenance();
  }

  [[nodiscard]] std::vector<std::uint8_t> finish(std::uint32_t format = 0) const {
    std::vector<std::uint8_t> file;
    file.push_back(static_cast<std::uint8_t>('M'));
    file.push_back(static_cast<std::uint8_t>('P'));
    file.push_back(static_cast<std::uint8_t>('F'));
    file.push_back(static_cast<std::uint8_t>('S'));
    file.push_back(static_cast<std::uint8_t>('T'));
    file.push_back(static_cast<std::uint8_t>('O'));
    file.push_back(static_cast<std::uint8_t>('R'));
    file.push_back(0);
    detail::ByteWriter header(32);
    header.u32(format == 0 ? persistence_format_version : format);
    header.u32(0);
    header.u64(writer_.buffer().size());
    for (const auto byte : header.buffer()) {
      file.push_back(byte);
    }
    file.insert(file.end(), writer_.buffer().begin(), writer_.buffer().end());
    const std::uint64_t checksum =
        detail::fnv1a64(detail::fnv1a64_offset_basis, file.data(), file.size());
    detail::ByteWriter trailer(16);
    trailer.u64(checksum);
    for (const auto byte : trailer.buffer()) {
      file.push_back(byte);
    }
    return file;
  }

 private:
  void provenance() {
    writer_.string("provenance-publisher", 128);
    writer_.string("provenance-boot", 128);
    writer_.u64(1);
    writer_.string("provenance-attempt", 128);
    writer_.u64(1);
    writer_.u8(static_cast<std::uint8_t>(MembershipCause::DECLARED));
  }

  mutable detail::ByteWriter writer_;
};

[[nodiscard]] std::vector<std::uint8_t> simple_store() {
  StoreBuilder builder;
  builder.epoch(1);
  builder.authority_generation(1);
  builder.fence_count(0);
  builder.set_count(1);
  builder.begin_set("store-set-1", "fabric-a", "ns-a", "name-a", 1, 1, 1,
                    static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                    static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
  builder.member_count(1);
  builder.member("store-member-1", "store-path-1", 1, 1,
                 static_cast<std::uint8_t>(MemberLifecycle::CURRENT),
                 static_cast<std::uint8_t>(MemberCurrentness::CURRENT), true);
  return builder.finish();
}

}  // namespace

MPF_TEST(store_round_trips_every_durable_field) {
  mpf_test::TempDirectory directory("roundtrip");
  const std::string path = directory.path("store.bin");
  mpf_test::FabricFixture fixture;
  const MultipathSetId first = fixture.build_set("roundtrip-a", 2, 3);
  const MultipathSetId second = fixture.build_set("roundtrip-b", 1, 2);
  MPF_REQUIRE(first.valid());
  MPF_REQUIRE(second.valid());
  MPF_REQUIRE(fixture.engine().revoke_set(fixture.context(), second,
                                          RevocationReason::OPERATOR_REQUEST, "test")
                  .succeeded());
  const auto before = fixture.engine().snapshot(first);
  MPF_REQUIRE(before.has_value());

  const FabricOutcome saved = fixture.engine().save_store(path);
  MPF_CHECK(saved.succeeded());
  MPF_CHECK_EQ(saved.code, OutcomeCode::STORE_SAVED);

  StoreStatistics statistics;
  MPF_REQUIRE(FabricEngine::inspect_store_file(path, statistics).succeeded());
  MPF_CHECK_EQ(statistics.set_count, std::size_t{2});
  MPF_CHECK_EQ(statistics.member_count, std::size_t{5});
  MPF_CHECK_EQ(statistics.revocation_count, std::size_t{1});

  FabricEngine recovered;
  const FabricOutcome loaded = recovered.load_store(path);
  MPF_CHECK(loaded.succeeded());
  MPF_CHECK_EQ(loaded.code, OutcomeCode::RECOVERED);
  MPF_CHECK_EQ(recovered.set_count(), std::size_t{2});
  MPF_CHECK_EQ(recovered.epoch().value(), fixture.engine().epoch().value() + 1);

  const auto after = recovered.snapshot(first);
  MPF_REQUIRE(after.has_value());
  MPF_CHECK_EQ(after->member_count, before->member_count);
  MPF_CHECK_EQ(after->membership_generation.value(), before->membership_generation.value());
  MPF_CHECK_EQ(after->minimum_usable_members, before->minimum_usable_members);
  for (std::size_t index = 0; index < before->members.size(); ++index) {
    MPF_CHECK_EQ(after->members[index].path_id.view(), before->members[index].path_id.view());
    MPF_CHECK_EQ(after->members[index].bound_authority_generation.value(),
                 before->members[index].bound_authority_generation.value());
  }
  const auto revoked = recovered.snapshot(second);
  MPF_REQUIRE(revoked.has_value());
  MPF_REQUIRE(revoked->revocation.has_value());
  MPF_CHECK_EQ(revoked->revocation->reason, RevocationReason::OPERATOR_REQUEST);
  MPF_CHECK_EQ(revoked->revocation->detail, std::string("test"));
}

MPF_TEST(recovery_is_conservative_and_never_restores_live_authority) {
  mpf_test::TempDirectory directory("recovery");
  const std::string path = directory.path("store.bin");
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("recovery", 2, 3);
  MPF_REQUIRE(set_id.valid());
  const auto before = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(before.has_value());
  MPF_CHECK_EQ(before->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(before->readiness, RouteReadiness::READY);
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());

  FabricEngine recovered;
  MPF_REQUIRE(recovered.load_store(path).succeeded());
  const auto after = recovered.snapshot(set_id);
  MPF_REQUIRE(after.has_value());
  // The durable description survives exactly.
  MPF_CHECK_EQ(after->member_count, before->member_count);
  MPF_CHECK_EQ(after->generation.value(), before->generation.value());
  MPF_CHECK_EQ(after->membership_generation.value(), before->membership_generation.value());
  // Live currentness does not.
  MPF_CHECK_EQ(after->currentness, SetCurrentness::REVALIDATION_REQUIRED);
  MPF_CHECK_EQ(after->readiness, RouteReadiness::REVALIDATION_REQUIRED);
  MPF_CHECK(after->currentness != SetCurrentness::CURRENT);
  MPF_CHECK_EQ(after->governing_epoch.value(), recovered.epoch().value());
  // No publisher authority was restored.
  MPF_CHECK_EQ(recovered.describe_authority().registrations.size(), std::size_t{0});
  MPF_CHECK(!recovered.is_fenced(fixture.publisher(), fixture.boot()));

  // The old epoch and old worker boot cannot mutate the recovered state.
  MutationContext stale = fixture.context();
  const FabricOutcome rejected = recovered.revalidate_set(stale, set_id);
  MPF_CHECK(!rejected.succeeded());
  MPF_CHECK_EQ(rejected.code, OutcomeCode::STALE_EPOCH);

  // A fresh registration and revalidation restore live currentness.
  const PublisherId publisher = PublisherId::require("recovery-publisher");
  const WorkerBootId boot = WorkerBootId::require("recovery-boot");
  const SessionId session = SessionId::require("recovery-session");
  AuthorityScope scope;
  scope.fabric = FabricId::require("fabric-test");
  scope.name_space = MultipathNamespace::require("ns-test");
  MPF_REQUIRE(recovered.register_publisher(publisher, boot, scope, session).succeeded());
  MutationContext fresh;
  fresh.epoch = recovered.epoch();
  fresh.publisher = publisher;
  fresh.worker_boot = boot;
  fresh.session = session;
  // Path Authority views are consumed, not owned: after a coordinator restart the
  // Path Authority bridge must re-declare what Path Authority currently reports.
  for (int index = 0; index < 3; ++index) {
    PathAuthorityView view;
    view.path = PathId::require("path-recovery-" + std::to_string(index));
    view.generation = PathAuthorityGeneration::require(1);
    view.state = PathAuthorityState::AUTHORIZED;
    fresh.attempt =
        MutationAttemptId::require("recovery-declare-" + std::to_string(index));
    MPF_REQUIRE(recovered.declare_path_authority(fresh, view).succeeded());
  }
  fresh.attempt = MutationAttemptId::require("recovery-attempt-1");
  MPF_REQUIRE(recovered.revalidate_set(fresh, set_id).succeeded());
  const auto live = recovered.snapshot(set_id);
  MPF_REQUIRE(live.has_value());
  MPF_CHECK_EQ(live->currentness, SetCurrentness::CURRENT);
  MPF_CHECK_EQ(live->lifecycle, SetLifecycle::ACTIVE);
  MPF_CHECK_EQ(live->readiness, RouteReadiness::READY);
}

MPF_TEST(repeated_restarts_advance_the_epoch_monotonically) {
  mpf_test::TempDirectory directory("restarts");
  const std::string path = directory.path("store.bin");
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("restarts", 1, 2);
  MPF_REQUIRE(set_id.valid());
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());

  std::uint64_t previous_epoch = fixture.engine().epoch().value();
  std::uint64_t previous_authority = fixture.engine().authority_generation().value();
  for (int restart = 0; restart < 5; ++restart) {
    FabricEngine engine;
    const FabricOutcome loaded = engine.load_store(path);
    MPF_REQUIRE(loaded.succeeded());
    MPF_CHECK_MSG(engine.epoch().value() > previous_epoch,
                  "epoch must advance on every restart");
    MPF_CHECK(engine.authority_generation().value() > previous_authority);
    previous_epoch = engine.epoch().value();
    previous_authority = engine.authority_generation().value();
    MPF_REQUIRE(engine.save_store(path).succeeded());
  }
  MPF_CHECK_EQ(previous_epoch, std::uint64_t{6});
}

MPF_TEST(previous_generation_backup_is_used_when_the_primary_is_corrupt) {
  mpf_test::TempDirectory directory("backup");
  const std::string path = directory.path("store.bin");
  mpf_test::FabricFixture fixture;
  const MultipathSetId first = fixture.build_set("backup-a", 1, 1);
  MPF_REQUIRE(first.valid());
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());
  const MultipathSetId second = fixture.build_set("backup-b", 1, 1);
  MPF_REQUIRE(second.valid());
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());
  MPF_CHECK(std::filesystem::exists(path + ".bak"));

  std::vector<std::uint8_t> bytes = mpf_test::read_bytes(path);
  MPF_REQUIRE(bytes.size() > 32);
  bytes[bytes.size() - 10] ^= 0xFFU;
  mpf_test::write_bytes(path, bytes);

  FabricEngine recovered;
  const FabricOutcome loaded = recovered.load_store(path);
  MPF_CHECK(loaded.succeeded());
  MPF_CHECK_EQ(loaded.code, OutcomeCode::RECOVERED);
  // The backup holds the state before the second save, so only the first set is
  // present.
  MPF_CHECK_EQ(recovered.set_count(), std::size_t{1});
  MPF_CHECK(recovered.snapshot(second).has_value() == false);
  StoreStatistics statistics;
  MPF_REQUIRE(FabricEngine::inspect_store_file(path, statistics).succeeded());
  MPF_CHECK(statistics.recovered_from_backup);
}

MPF_TEST(store_rejects_malformed_files) {
  mpf_test::TempDirectory directory("corruption");
  const std::vector<std::uint8_t> good = simple_store();
  MPF_REQUIRE(good.size() > 40);

  const auto expect_rejected = [&](const std::string& name,
                                   const std::vector<std::uint8_t>& bytes,
                                   OutcomeCode expected) {
    const std::string path = directory.path(name);
    mpf_test::write_bytes(path, bytes);
    StoreStatistics statistics;
    const FabricOutcome outcome = FabricEngine::inspect_store_file(path, statistics);
    MPF_CHECK_MSG(!outcome.succeeded(), name + " was accepted");
    MPF_CHECK_MSG(outcome.code == expected,
                  name + " expected " + std::string(to_string(expected)) + " got " +
                      std::string(to_string(outcome.code)));
    FabricEngine engine;
    MPF_CHECK(!engine.load_store(path).succeeded());
  };

  // Empty file.
  expect_rejected("empty.bin", {}, OutcomeCode::STORE_CORRUPT);
  // Bad magic.
  std::vector<std::uint8_t> bad_magic = good;
  bad_magic[0] = 'X';
  expect_rejected("bad-magic.bin", bad_magic, OutcomeCode::STORE_CORRUPT);
  // Unsupported format version.
  std::vector<std::uint8_t> bad_version = good;
  bad_version[8] = 99;
  expect_rejected("bad-version.bin", bad_version, OutcomeCode::STORE_VERSION_UNSUPPORTED);
  // Non-zero reserved field.
  std::vector<std::uint8_t> bad_reserved = good;
  bad_reserved[12] = 1;
  expect_rejected("bad-reserved.bin", bad_reserved, OutcomeCode::STORE_CORRUPT);
  // Corrupt checksum.
  std::vector<std::uint8_t> bad_checksum = good;
  bad_checksum[bad_checksum.size() - 1] ^= 0x01U;
  expect_rejected("bad-checksum.bin", bad_checksum, OutcomeCode::INTEGRITY_ERROR);
  // Trailing bytes after the framed store.
  std::vector<std::uint8_t> trailing = good;
  trailing.push_back(0x00);
  expect_rejected("trailing.bin", trailing, OutcomeCode::STORE_CORRUPT);

  // Truncation at every length below the full file.
  std::uint64_t truncations_checked = 0;
  for (std::size_t length = 0; length < good.size(); ++length) {
    const std::string path = directory.path("trunc-" + std::to_string(length) + ".bin");
    std::vector<std::uint8_t> truncated(good.begin(), good.begin() + static_cast<long>(length));
    mpf_test::write_bytes(path, truncated);
    StoreStatistics statistics;
    MPF_CHECK(!FabricEngine::inspect_store_file(path, statistics).succeeded());
    ++truncations_checked;
  }
  MPF_CHECK_EQ(truncations_checked, static_cast<std::uint64_t>(good.size()));
}

MPF_TEST(store_rejects_duplicate_and_dangling_records) {
  mpf_test::TempDirectory directory("structure");

  // Duplicate set identity.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(2);
    for (int index = 0; index < 2; ++index) {
      builder.begin_set("duplicate-set", "fabric-a", "ns-a", "name-a", 1, 1, 1,
                        static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                        static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
      builder.member_count(0);
    }
    const std::string path = directory.path("duplicate-set.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    const FabricOutcome outcome = engine.load_store(path);
    MPF_CHECK(!outcome.succeeded());
    MPF_CHECK_EQ(outcome.code, OutcomeCode::STORE_DUPLICATE_SET);
  }
  // Duplicate semantic key with distinct identities.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(2);
    builder.begin_set("key-set-1", "fabric-a", "ns-a", "same-name", 1, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
    builder.member_count(0);
    builder.begin_set("key-set-2", "fabric-a", "ns-a", "same-name", 1, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
    builder.member_count(0);
    const std::string path = directory.path("duplicate-key.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    const FabricOutcome outcome = engine.load_store(path);
    MPF_CHECK(!outcome.succeeded());
    MPF_CHECK_EQ(outcome.code, OutcomeCode::STORE_DUPLICATE_SET);
  }
  // Duplicate member inside one set.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(1);
    builder.begin_set("member-set", "fabric-a", "ns-a", "member-name", 1, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
    builder.member_count(2);
    builder.member("member-1", "path-1", 1, 1,
                   static_cast<std::uint8_t>(MemberLifecycle::CURRENT),
                   static_cast<std::uint8_t>(MemberCurrentness::CURRENT), true);
    builder.member("member-2", "path-1", 1, 1,
                   static_cast<std::uint8_t>(MemberLifecycle::CURRENT),
                   static_cast<std::uint8_t>(MemberCurrentness::CURRENT), true);
    const std::string path = directory.path("duplicate-member.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    const FabricOutcome outcome = engine.load_store(path);
    MPF_CHECK(!outcome.succeeded());
    MPF_CHECK_EQ(outcome.code, OutcomeCode::STORE_DUPLICATE_MEMBER);
  }
  // Impossible generation: zero.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(1);
    builder.begin_set("zero-generation", "fabric-a", "ns-a", "zero-name", 0, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
    builder.member_count(0);
    const std::string path = directory.path("zero-generation.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    const FabricOutcome outcome = engine.load_store(path);
    MPF_CHECK(!outcome.succeeded());
    MPF_CHECK_EQ(outcome.code, OutcomeCode::STORE_CORRUPT);
  }
  // Malformed lifecycle enumerator.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(1);
    builder.begin_set("bad-lifecycle", "fabric-a", "ns-a", "bad-name", 1, 1, 1, 200,
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 1, false, 1);
    builder.member_count(0);
    const std::string path = directory.path("bad-lifecycle.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    MPF_CHECK_EQ(engine.load_store(path).code, OutcomeCode::STORE_CORRUPT);
  }
  // Minimum requirement above the allowed bound.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(1);
    builder.begin_set("bad-threshold", "fabric-a", "ns-a", "threshold-name", 1, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::ACTIVE),
                      static_cast<std::uint8_t>(SetCurrentness::CURRENT), true, 100000, false, 1);
    builder.member_count(0);
    const std::string path = directory.path("bad-threshold.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    MPF_CHECK_EQ(engine.load_store(path).code, OutcomeCode::STORE_CORRUPT);
  }
  // Absurd set count.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(4000000000U);
    const std::string path = directory.path("absurd-count.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    MPF_CHECK_EQ(engine.load_store(path).code, OutcomeCode::STORE_CORRUPT);
  }
  // A revoked set without a revocation record is impossible.
  {
    StoreBuilder builder;
    builder.epoch(1);
    builder.authority_generation(1);
    builder.fence_count(0);
    builder.set_count(1);
    builder.begin_set("revoked-without-record", "fabric-a", "ns-a", "revoked-name", 1, 1, 1,
                      static_cast<std::uint8_t>(SetLifecycle::REVOKED),
                      static_cast<std::uint8_t>(SetCurrentness::REVALIDATION_REQUIRED), true, 1,
                      false, 1);
    builder.member_count(0);
    const std::string path = directory.path("revoked-without-record.bin");
    mpf_test::write_bytes(path, builder.finish());
    FabricEngine engine;
    MPF_CHECK_EQ(engine.load_store(path).code, OutcomeCode::STORE_CORRUPT);
  }
}

MPF_TEST(store_write_is_atomic_and_leaves_no_temporary_file) {
  mpf_test::TempDirectory directory("atomic");
  const std::string path = directory.path("store.bin");
  mpf_test::FabricFixture fixture;
  MPF_REQUIRE(fixture.build_set("atomic", 1, 2).valid());
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());
  MPF_CHECK(std::filesystem::exists(path));
  MPF_CHECK(!std::filesystem::exists(path + ".tmp"));
  // A second save rotates the previous file to the backup and leaves no
  // temporary behind.
  MPF_REQUIRE(fixture.engine().save_store(path).succeeded());
  MPF_CHECK(std::filesystem::exists(path));
  MPF_CHECK(std::filesystem::exists(path + ".bak"));
  MPF_CHECK(!std::filesystem::exists(path + ".tmp"));
  MPF_CHECK(fixture.engine().save_store("").code == OutcomeCode::MALFORMED_REQUEST);
  MPF_CHECK(fixture.engine().load_store("").code == OutcomeCode::MALFORMED_REQUEST);
  MPF_CHECK(fixture.engine()
                .load_store(directory.path("does-not-exist.bin"))
                .code == OutcomeCode::STORE_IO_ERROR);
}
