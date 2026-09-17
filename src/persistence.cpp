#include "engine_impl.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <vector>

#include "multipath_fabric/persistence.hpp"

namespace multipath_fabric {
namespace {

constexpr std::size_t kMaxIdLength = 128;
constexpr std::size_t kMaxShortText = 64;
constexpr std::size_t kMaxReasonText = 512;
constexpr std::uint64_t kMaxMembersPerSetHardBound = 1000000;

[[nodiscard]] std::uint64_t encode_checksum(const std::vector<std::uint8_t>& bytes,
                                            std::size_t length) {
  return detail::fnv1a64(detail::fnv1a64_offset_basis, bytes.data(), length);
}

[[nodiscard]] FabricOutcome corrupt(std::string detail_text) {
  return make_rejection(OutcomeCode::STORE_CORRUPT, std::move(detail_text));
}

void write_provenance(detail::ByteWriter& writer, const MembershipProvenance& provenance) {
  writer.string(provenance.publisher.valid() ? provenance.publisher.view() : std::string_view(""),
                kMaxIdLength);
  writer.string(provenance.worker_boot.valid() ? provenance.worker_boot.view() : std::string_view(""),
                kMaxIdLength);
  writer.u64(provenance.epoch.valid() ? provenance.epoch.value() : 0);
  writer.string(provenance.attempt.valid() ? provenance.attempt.view() : std::string_view(""),
                kMaxIdLength);
  writer.u64(provenance.set_generation.valid() ? provenance.set_generation.value() : 0);
  writer.u8(static_cast<std::uint8_t>(provenance.cause));
}

[[nodiscard]] bool read_optional_id(detail::ByteReader& reader, std::string& out) {
  const auto present = reader.boolean();
  if (!present.has_value()) {
    return false;
  }
  if (!*present) {
    out.clear();
    return true;
  }
  const auto value = reader.string(kMaxIdLength);
  if (!value.has_value()) {
    return false;
  }
  out = *value;
  return true;
}

[[nodiscard]] bool read_provenance(detail::ByteReader& reader, MembershipProvenance& out) {
  const auto publisher = reader.string(kMaxIdLength);
  const auto boot = reader.string(kMaxIdLength);
  const auto epoch = reader.u64();
  const auto attempt = reader.string(kMaxIdLength);
  const auto set_generation = reader.u64();
  const auto cause = reader.u8();
  if (!publisher.has_value() || !boot.has_value() || !epoch.has_value() ||
      !attempt.has_value() || !set_generation.has_value() || !cause.has_value()) {
    return false;
  }
  if (!valid_membership_cause(*cause)) {
    reader.fail();
    return false;
  }
  if (*epoch == 0 || *set_generation == 0) {
    reader.fail();
    return false;
  }
  const auto publisher_id = PublisherId::parse(*publisher);
  const auto boot_id = WorkerBootId::parse(*boot);
  const auto attempt_id = MutationAttemptId::parse(*attempt);
  const auto epoch_value = CoordinatorEpoch::from_value(*epoch);
  const auto generation_value = MultipathSetGeneration::from_value(*set_generation);
  if (!publisher_id.has_value() || !boot_id.has_value() || !attempt_id.has_value() ||
      !epoch_value.has_value() || !generation_value.has_value()) {
    reader.fail();
    return false;
  }
  out.publisher = *publisher_id;
  out.worker_boot = *boot_id;
  out.epoch = *epoch_value;
  out.attempt = *attempt_id;
  out.set_generation = *generation_value;
  out.cause = static_cast<MembershipCause>(*cause);
  return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::save_store(const std::string& path) const {
  if (path.empty()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "save_store requires a file path");
  }
  detail::ByteWriter payload(impl_->config.limits.max_persistence_record_bytes);
  {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex);
    payload.u32(persistence_format_version);
    payload.u64(impl_->current_epoch.value());
    payload.u64(impl_->current_authority_generation.value());
    payload.u32(static_cast<std::uint32_t>(impl_->fences.size()));
    payload.u32(static_cast<std::uint32_t>(impl_->sets.size()));
    for (const auto& entry : impl_->fences) {
      payload.string(entry.second.publisher.view(), kMaxIdLength);
      payload.string(entry.second.worker_boot.view(), kMaxIdLength);
      payload.u64(entry.second.epoch.value());
      payload.string(entry.second.cause, kMaxShortText);
    }
    for (const auto& entry : impl_->sets) {
      const detail::SetRecord& record = entry.second;
      payload.string(record.id.view(), kMaxIdLength);
      payload.string(record.key.fabric.view(), kMaxIdLength);
      payload.string(record.key.name_space.view(), kMaxIdLength);
      payload.string(record.key.name.view(), kMaxIdLength);
      payload.u64(record.generation.value());
      payload.u64(record.membership_generation.value());
      payload.u64(record.authority_generation.value());
      payload.u8(static_cast<std::uint8_t>(record.lifecycle));
      payload.u8(static_cast<std::uint8_t>(record.currentness));
      payload.boolean(record.admin_enabled);
      payload.u64(record.minimum_usable_members);
      payload.boolean(record.conditional_authority_permitted);
      payload.u64(record.governing_epoch.value());
      payload.u8(record.superseded_by.has_value() ? 1U : 0U);
      if (record.superseded_by.has_value()) {
        payload.string(record.superseded_by->view(), kMaxIdLength);
      }
      payload.u8(record.supersedes.has_value() ? 1U : 0U);
      if (record.supersedes.has_value()) {
        payload.string(record.supersedes->view(), kMaxIdLength);
      }
      payload.u8(record.revocation.has_value() ? 1U : 0U);
      if (record.revocation.has_value()) {
        payload.u8(static_cast<std::uint8_t>(record.revocation->reason));
        payload.string(record.revocation->detail, kMaxReasonText);
        payload.u64(record.revocation->generation.value());
        payload.u64(record.revocation->authority_generation.value());
        payload.u64(record.revocation->epoch.value());
        payload.string(record.revocation->publisher.view(), kMaxIdLength);
      }
      payload.string(record.withdrawal_reason, kMaxReasonText);
      write_provenance(payload, record.provenance);
      payload.u32(static_cast<std::uint32_t>(record.members.size()));
      for (const auto& member_entry : record.members) {
        const detail::MemberRecord& member = member_entry.second;
        payload.string(member.id.view(), kMaxIdLength);
        payload.string(member.path_id.view(), kMaxIdLength);
        payload.u64(member.bound_authority_generation.value());
        payload.u64(member.generation.value());
        payload.u8(static_cast<std::uint8_t>(member.lifecycle));
        payload.u8(static_cast<std::uint8_t>(member.currentness));
        payload.boolean(member.admin_enabled);
        payload.u64(member.invalidation_watermark.value());
        payload.u32(member.pending_revalidations);
        payload.u8(member.predecessor.has_value() ? 1U : 0U);
        if (member.predecessor.has_value()) {
          payload.string(member.predecessor->view(), kMaxIdLength);
        }
        payload.u8(member.successor.has_value() ? 1U : 0U);
        if (member.successor.has_value()) {
          payload.string(member.successor->view(), kMaxIdLength);
        }
        payload.u8(member.observed_authority_generation.has_value() &&
                           member.observed_authority_state.has_value()
                       ? 1U
                       : 0U);
        if (member.observed_authority_generation.has_value() &&
            member.observed_authority_state.has_value()) {
          payload.u64(member.observed_authority_generation->value());
          payload.u8(static_cast<std::uint8_t>(*member.observed_authority_state));
        }
        write_provenance(payload, member.provenance);
      }
    }
  }
  if (payload.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "store payload exceeds max_persistence_record_bytes " +
                              std::to_string(impl_->config.limits.max_persistence_record_bytes));
  }

  const std::vector<std::uint8_t> body = payload.buffer();
  if (body.size() > impl_->config.limits.max_persistence_record_bytes) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "store payload exceeds max_persistence_record_bytes");
  }
  const std::uint64_t total = static_cast<std::uint64_t>(store_header_size) + body.size() +
                              sizeof(std::uint64_t);
  if (total > impl_->config.limits.max_store_bytes) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "store size " + std::to_string(total) + " exceeds max_store_bytes " +
                              std::to_string(impl_->config.limits.max_store_bytes));
  }

  std::vector<std::uint8_t> file;
  file.reserve(static_cast<std::size_t>(total));
  const std::string magic(store_magic);
  for (std::size_t i = 0; i < store_magic_size; ++i) {
    file.push_back(i < magic.size() ? static_cast<std::uint8_t>(magic[i]) : 0U);
  }
  detail::ByteWriter header(64);
  header.u32(persistence_format_version);
  header.u32(0);
  header.u64(body.size());
  for (const auto byte : header.buffer()) {
    file.push_back(byte);
  }
  file.insert(file.end(), body.begin(), body.end());
  detail::ByteWriter trailer(16);
  trailer.u64(encode_checksum(file, file.size()));
  for (const auto byte : trailer.buffer()) {
    file.push_back(byte);
  }

  const std::filesystem::path target(path);
  const std::filesystem::path temporary = target.string() + ".tmp";
  const std::filesystem::path backup = target.string() + ".bak";
  {
    std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
    if (!stream) {
      return make_rejection(OutcomeCode::STORE_IO_ERROR,
                            "cannot open temporary store file: " + temporary.string());
    }
    stream.write(reinterpret_cast<const char*>(file.data()),
                 static_cast<std::streamsize>(file.size()));
    stream.flush();
    if (!stream) {
      stream.close();
      std::error_code ignored;
      std::filesystem::remove(temporary, ignored);
      return make_rejection(OutcomeCode::STORE_IO_ERROR,
                            "cannot write temporary store file: " + temporary.string());
    }
  }
  std::error_code error;
  if (std::filesystem::exists(target, error)) {
    std::filesystem::remove(backup, error);
    std::filesystem::rename(target, backup, error);
    if (error) {
      return make_rejection(OutcomeCode::STORE_IO_ERROR,
                            "cannot rotate the previous store file to " + backup.string() + ": " +
                                error.message());
    }
  }
  std::filesystem::rename(temporary, target, error);
  if (error) {
    return make_rejection(OutcomeCode::STORE_IO_ERROR,
                          "cannot atomically replace the store file " + target.string() + ": " +
                              error.message());
  }
  FabricOutcome outcome = make_outcome(OutcomeCode::STORE_SAVED,
                                       "saved store to " + target.string());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

namespace {

struct DecodedStore {
  CoordinatorEpoch epoch;
  MultipathAuthorityGeneration authority_generation;
  std::vector<FenceRecord> fences;
  std::vector<detail::SetRecord> sets;
  detail::Digest128 payload_digest;
};

[[nodiscard]] FabricOutcome decode_store(const std::vector<std::uint8_t>& file,
                                         const Limits& limits, DecodedStore& out) {
  if (file.size() < store_header_size + sizeof(std::uint64_t)) {
    return corrupt("store file is shorter than the minimum framed length");
  }
  const std::string magic(store_magic);
  for (std::size_t i = 0; i < store_magic_size; ++i) {
    const std::uint8_t expected = i < magic.size() ? static_cast<std::uint8_t>(magic[i]) : 0U;
    if (file[i] != expected) {
      return corrupt("store magic does not match");
    }
  }
  detail::ByteReader header(file.data() + store_magic_size,
                            store_header_size - store_magic_size);
  const auto format = header.u32();
  const auto reserved = header.u32();
  const auto payload_length = header.u64();
  if (!format.has_value() || !reserved.has_value() || !payload_length.has_value()) {
    return corrupt("store header is truncated");
  }
  if (*reserved != 0) {
    return corrupt("store header reserved field is not zero");
  }
  if (*format != persistence_format_version) {
    return make_rejection(OutcomeCode::STORE_VERSION_UNSUPPORTED,
                          "store format version " + std::to_string(*format) +
                              " is not supported; this build writes and reads version " +
                              std::to_string(persistence_format_version));
  }
  if (*payload_length > limits.max_persistence_record_bytes) {
    return corrupt("store payload length exceeds max_persistence_record_bytes");
  }
  const std::uint64_t expected_size =
      static_cast<std::uint64_t>(store_header_size) + *payload_length + sizeof(std::uint64_t);
  if (expected_size != file.size()) {
    return corrupt("store length mismatch: header declares " + std::to_string(expected_size) +
                   " bytes but the file holds " + std::to_string(file.size()));
  }
  if (file.size() > limits.max_store_bytes) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "store exceeds max_store_bytes");
  }
  const std::size_t covered = static_cast<std::size_t>(store_header_size) +
                              static_cast<std::size_t>(*payload_length);
  detail::ByteReader trailer(file.data() + covered, sizeof(std::uint64_t));
  const auto stored_checksum = trailer.u64();
  if (!stored_checksum.has_value()) {
    return corrupt("store trailer is truncated");
  }
  const std::uint64_t actual = encode_checksum(file, covered);
  if (actual != *stored_checksum) {
    return make_rejection(OutcomeCode::INTEGRITY_ERROR,
                          "store checksum mismatch: stored " + std::to_string(*stored_checksum) +
                              " computed " + std::to_string(actual));
  }

  detail::ByteReader reader(file.data() + store_header_size,
                            static_cast<std::size_t>(*payload_length));
  out.payload_digest = detail::DigestBuilder{}.finish();
  {
    detail::DigestBuilder builder;
    builder.absorb_bytes(std::string_view(
        reinterpret_cast<const char*>(file.data() + store_header_size),
        static_cast<std::size_t>(*payload_length)));
    out.payload_digest = builder.finish();
  }

  const auto payload_version = reader.u32();
  const auto epoch = reader.u64();
  const auto authority_generation = reader.u64();
  const auto fence_count = reader.u32();
  const auto set_count = reader.u32();
  if (!payload_version.has_value() || !epoch.has_value() || !authority_generation.has_value() ||
      !fence_count.has_value() || !set_count.has_value()) {
    return corrupt("store payload header is truncated");
  }
  if (*payload_version != persistence_format_version) {
    return make_rejection(OutcomeCode::STORE_VERSION_UNSUPPORTED,
                          "store payload version " + std::to_string(*payload_version) +
                              " is not supported");
  }
  const auto epoch_value = CoordinatorEpoch::from_value(*epoch);
  const auto authority_value = MultipathAuthorityGeneration::from_value(*authority_generation);
  if (!epoch_value.has_value() || !authority_value.has_value()) {
    return corrupt("store declares an impossible epoch or authority generation");
  }
  out.epoch = *epoch_value;
  out.authority_generation = *authority_value;
  if (*set_count > limits.max_sets) {
    return corrupt("store declares " + std::to_string(*set_count) +
                   " sets which exceeds max_sets");
  }
  if (*fence_count > limits.max_publishers * 64ULL + 64ULL) {
    return corrupt("store declares an absurd fence count");
  }

  out.fences.reserve(*fence_count);
  for (std::uint32_t i = 0; i < *fence_count; ++i) {
    const auto publisher = reader.string(kMaxIdLength);
    const auto boot = reader.string(kMaxIdLength);
    const auto fence_epoch = reader.u64();
    const auto cause = reader.string(kMaxShortText);
    if (!publisher.has_value() || !boot.has_value() || !fence_epoch.has_value() ||
        !cause.has_value()) {
      return corrupt("store fence record is truncated");
    }
    const auto publisher_id = PublisherId::parse(*publisher);
    const auto boot_id = WorkerBootId::parse(*boot);
    const auto epoch_parsed = CoordinatorEpoch::from_value(*fence_epoch);
    if (!publisher_id.has_value() || !boot_id.has_value() || !epoch_parsed.has_value()) {
      return corrupt("store fence record carries an impossible identity or epoch");
    }
    FenceRecord record;
    record.publisher = *publisher_id;
    record.worker_boot = *boot_id;
    record.epoch = *epoch_parsed;
    record.cause = *cause;
    out.fences.push_back(std::move(record));
  }

  std::uint64_t total_members = 0;
  out.sets.reserve(*set_count);
  for (std::uint32_t i = 0; i < *set_count; ++i) {
    detail::SetRecord record;
    const auto set_id = reader.string(kMaxIdLength);
    const auto fabric = reader.string(kMaxIdLength);
    const auto name_space = reader.string(kMaxIdLength);
    const auto name = reader.string(kMaxIdLength);
    const auto generation = reader.u64();
    const auto membership_generation = reader.u64();
    const auto authority_generation_value = reader.u64();
    const auto lifecycle = reader.u8();
    const auto currentness = reader.u8();
    const auto admin_enabled = reader.boolean();
    const auto minimum = reader.u64();
    const auto conditional = reader.boolean();
    const auto governing_epoch = reader.u64();
    if (!set_id.has_value() || !fabric.has_value() || !name_space.has_value() ||
        !name.has_value() || !generation.has_value() || !membership_generation.has_value() ||
        !authority_generation_value.has_value() || !lifecycle.has_value() ||
        !currentness.has_value() || !admin_enabled.has_value() || !minimum.has_value() ||
        !conditional.has_value() || !governing_epoch.has_value()) {
      return corrupt("store set record is truncated");
    }
    const auto set_id_value = MultipathSetId::parse(*set_id);
    const auto fabric_value = FabricId::parse(*fabric);
    const auto namespace_value = MultipathNamespace::parse(*name_space);
    const auto name_value = MultipathSetName::parse(*name);
    const auto generation_value = MultipathSetGeneration::from_value(*generation);
    const auto membership_value = MembershipGeneration::from_value(*membership_generation);
    const auto authority_value2 =
        MultipathAuthorityGeneration::from_value(*authority_generation_value);
    const auto governing_value = CoordinatorEpoch::from_value(*governing_epoch);
    if (!set_id_value.has_value() || !fabric_value.has_value() || !namespace_value.has_value() ||
        !name_value.has_value() || !generation_value.has_value() ||
        !membership_value.has_value() || !authority_value2.has_value() ||
        !governing_value.has_value()) {
      return corrupt("store set record carries an impossible identity or generation");
    }
    if (!valid_set_lifecycle(*lifecycle)) {
      return corrupt("store set record carries a malformed lifecycle enumerator");
    }
    if (!valid_set_currentness(*currentness)) {
      return corrupt("store set record carries a malformed currentness enumerator");
    }
    if (*minimum > limits.max_members_per_set) {
      return corrupt("store set record declares a minimum usable-member requirement above "
                     "max_members_per_set");
    }
    record.id = *set_id_value;
    record.key.fabric = *fabric_value;
    record.key.name_space = *namespace_value;
    record.key.name = *name_value;
    record.generation = *generation_value;
    record.membership_generation = *membership_value;
    record.authority_generation = *authority_value2;
    record.lifecycle = static_cast<SetLifecycle>(*lifecycle);
    record.currentness = static_cast<SetCurrentness>(*currentness);
    record.admin_enabled = *admin_enabled;
    record.minimum_usable_members = *minimum;
    record.conditional_authority_permitted = *conditional;
    record.governing_epoch = *governing_value;

    std::string optional;
    if (!read_optional_id(reader, optional)) {
      return corrupt("store set supersession field is truncated");
    }
    if (!optional.empty()) {
      const auto parsed = MultipathSetId::parse(optional);
      if (!parsed.has_value()) {
        return corrupt("store set supersession field carries an impossible set identity");
      }
      record.superseded_by = *parsed;
    }
    if (!read_optional_id(reader, optional)) {
      return corrupt("store set predecessor field is truncated");
    }
    if (!optional.empty()) {
      const auto parsed = MultipathSetId::parse(optional);
      if (!parsed.has_value()) {
        return corrupt("store set predecessor field carries an impossible set identity");
      }
      record.supersedes = *parsed;
    }
    const auto has_revocation = reader.boolean();
    if (!has_revocation.has_value()) {
      return corrupt("store revocation flag is truncated");
    }
    if (*has_revocation) {
      const auto reason = reader.u8();
      const auto revocation_detail = reader.string(kMaxReasonText);
      const auto revocation_generation = reader.u64();
      const auto revocation_authority = reader.u64();
      const auto revocation_epoch = reader.u64();
      const auto revocation_publisher = reader.string(kMaxIdLength);
      if (!reason.has_value() || !revocation_detail.has_value() ||
          !revocation_generation.has_value() || !revocation_authority.has_value() ||
          !revocation_epoch.has_value() || !revocation_publisher.has_value()) {
        return corrupt("store revocation record is truncated");
      }
      if (!valid_revocation_reason(*reason)) {
        return corrupt("store revocation record carries a malformed reason enumerator");
      }
      const auto revocation_generation_value =
          MultipathSetGeneration::from_value(*revocation_generation);
      const auto revocation_authority_value =
          MultipathAuthorityGeneration::from_value(*revocation_authority);
      const auto revocation_epoch_value = CoordinatorEpoch::from_value(*revocation_epoch);
      const auto revocation_publisher_value = PublisherId::parse(*revocation_publisher);
      if (!revocation_generation_value.has_value() || !revocation_authority_value.has_value() ||
          !revocation_epoch_value.has_value() || !revocation_publisher_value.has_value()) {
        return corrupt("store revocation record carries an impossible generation or identity");
      }
      RevocationRecord revocation;
      revocation.set_id = record.id;
      revocation.reason = static_cast<RevocationReason>(*reason);
      revocation.detail = *revocation_detail;
      revocation.generation = *revocation_generation_value;
      revocation.authority_generation = *revocation_authority_value;
      revocation.epoch = *revocation_epoch_value;
      revocation.publisher = *revocation_publisher_value;
      record.revocation = std::move(revocation);
    }
    if (record.lifecycle == SetLifecycle::REVOKED && !record.revocation.has_value()) {
      return corrupt("store declares a revoked set without a revocation record");
    }
    const auto withdrawal = reader.string(kMaxReasonText);
    if (!withdrawal.has_value()) {
      return corrupt("store withdrawal reason is truncated");
    }
    record.withdrawal_reason = *withdrawal;
    if (!read_provenance(reader, record.provenance)) {
      return corrupt("store set provenance is truncated or malformed");
    }
    const auto member_count = reader.u32();
    if (!member_count.has_value()) {
      return corrupt("store member count is truncated");
    }
    if (*member_count > limits.max_members_per_set + limits.max_archived_members_per_set + 1ULL) {
      return corrupt("store set declares " + std::to_string(*member_count) +
                     " member records which exceeds the configured bound");
    }
    const auto next_total = detail::checked_add(total_members, *member_count);
    if (!next_total.has_value() || *next_total > limits.max_total_members) {
      return corrupt("store declares more members than max_total_members");
    }
    total_members = *next_total;
    std::uint64_t live_records = 0;
    for (std::uint32_t m = 0; m < *member_count; ++m) {
      detail::MemberRecord member;
      const auto member_id = reader.string(kMaxIdLength);
      const auto path = reader.string(kMaxIdLength);
      const auto bound_generation = reader.u64();
      const auto member_generation = reader.u64();
      const auto member_lifecycle = reader.u8();
      const auto member_currentness = reader.u8();
      const auto member_admin = reader.boolean();
      const auto watermark = reader.u64();
      const auto pending = reader.u32();
      if (!member_id.has_value() || !path.has_value() || !bound_generation.has_value() ||
          !member_generation.has_value() || !member_lifecycle.has_value() ||
          !member_currentness.has_value() || !member_admin.has_value() ||
          !watermark.has_value() || !pending.has_value()) {
        return corrupt("store member record is truncated");
      }
      const auto member_id_value = MultipathMemberId::parse(*member_id);
      const auto path_value = PathId::parse(*path);
      const auto bound_value = PathAuthorityGeneration::from_value(*bound_generation);
      const auto member_generation_value = MultipathMemberGeneration::from_value(*member_generation);
      if (!member_id_value.has_value() || !path_value.has_value() || !bound_value.has_value() ||
          !member_generation_value.has_value()) {
        return corrupt("store member record carries an impossible identity or generation");
      }
      if (!valid_member_lifecycle(*member_lifecycle)) {
        return corrupt("store member record carries a malformed lifecycle enumerator");
      }
      if (!valid_member_currentness(*member_currentness)) {
        return corrupt("store member record carries a malformed currentness enumerator");
      }
      if (*pending > limits.max_pending_revalidations_per_set) {
        return corrupt("store member record declares more pending revalidations than the bound");
      }
      member.id = *member_id_value;
      member.path_id = *path_value;
      member.bound_authority_generation = *bound_value;
      member.generation = *member_generation_value;
      member.lifecycle = static_cast<MemberLifecycle>(*member_lifecycle);
      member.currentness = static_cast<MemberCurrentness>(*member_currentness);
      member.admin_enabled = *member_admin;
      member.invalidation_watermark = Watermark(*watermark);
      member.pending_revalidations = *pending;
      if (!read_optional_id(reader, optional)) {
        return corrupt("store member predecessor field is truncated");
      }
      if (!optional.empty()) {
        const auto parsed = MultipathMemberId::parse(optional);
        if (!parsed.has_value()) {
          return corrupt("store member predecessor carries an impossible member identity");
        }
        member.predecessor = *parsed;
      }
      if (!read_optional_id(reader, optional)) {
        return corrupt("store member successor field is truncated");
      }
      if (!optional.empty()) {
        const auto parsed = MultipathMemberId::parse(optional);
        if (!parsed.has_value()) {
          return corrupt("store member successor carries an impossible member identity");
        }
        member.successor = *parsed;
      }
      const auto has_observation = reader.boolean();
      if (!has_observation.has_value()) {
        return corrupt("store member observation flag is truncated");
      }
      if (*has_observation) {
        const auto observed_generation = reader.u64();
        const auto observed_state = reader.u8();
        if (!observed_generation.has_value() || !observed_state.has_value()) {
          return corrupt("store member observation is truncated");
        }
        if (!valid_path_authority_state(*observed_state)) {
          return corrupt("store member observation carries a malformed state");
        }
        const auto parsed_generation =
            PathAuthorityGeneration::from_value(*observed_generation);
        if (!parsed_generation.has_value()) {
          return corrupt("store member observation carries an impossible generation");
        }
        member.observed_authority_generation = *parsed_generation;
        member.observed_authority_state = static_cast<PathAuthorityState>(*observed_state);
      }
      if (!read_provenance(reader, member.provenance)) {
        return corrupt("store member provenance is truncated or malformed");
      }
      if (record.members.find(member.path_id) != record.members.end()) {
        return make_rejection(OutcomeCode::STORE_DUPLICATE_MEMBER,
                              "store set " + record.id.str() +
                                  " contains the same exact path more than once");
      }
      if (record.member_index.find(member.id) != record.member_index.end()) {
        return make_rejection(OutcomeCode::STORE_DUPLICATE_MEMBER,
                              "store set " + record.id.str() +
                                  " contains the same member identity more than once");
      }
      if (member.lifecycle != MemberLifecycle::WITHDRAWN &&
          member.lifecycle != MemberLifecycle::SUPERSEDED &&
          member.lifecycle != MemberLifecycle::RETIRED) {
        ++live_records;
      }
      record.member_index[member.id] = member.path_id;
      record.members[member.path_id] = std::move(member);
    }
    if (live_records > limits.max_members_per_set) {
      return corrupt("store set " + record.id.str() + " declares " +
                     std::to_string(live_records) +
                     " live membership relations which exceeds max_members_per_set " +
                     std::to_string(limits.max_members_per_set));
    }
    record.usable_member_count = record.recompute_usable_members();
    out.sets.push_back(std::move(record));
  }

  if (!reader.at_end()) {
    return corrupt("store payload has " + std::to_string(reader.remaining()) +
                   " trailing byte(s) after the declared records");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

[[nodiscard]] FabricOutcome read_and_decode(const std::string& path, const Limits& limits,
                                            DecodedStore& out, bool& recovered_from_backup) {
  const std::filesystem::path target(path);
  const auto read_file = [](const std::filesystem::path& candidate,
                            std::vector<std::uint8_t>& buffer) -> FabricOutcome {
    std::ifstream stream(candidate, std::ios::binary);
    if (!stream) {
      return make_rejection(OutcomeCode::STORE_IO_ERROR,
                            "cannot open store file: " + candidate.string());
    }
    stream.seekg(0, std::ios::end);
    const std::streamoff length = stream.tellg();
    if (length < 0) {
      return make_rejection(OutcomeCode::STORE_IO_ERROR,
                            "cannot size store file: " + candidate.string());
    }
    stream.seekg(0, std::ios::beg);
    buffer.resize(static_cast<std::size_t>(length));
    if (length > 0) {
      stream.read(reinterpret_cast<char*>(buffer.data()), length);
      if (!stream) {
        return make_rejection(OutcomeCode::STORE_IO_ERROR,
                              "cannot read store file: " + candidate.string());
      }
    }
    return make_outcome(OutcomeCode::OK, std::string());
  };

  std::vector<std::uint8_t> buffer;
  FabricOutcome primary = read_file(target, buffer);
  if (primary.succeeded()) {
    primary = decode_store(buffer, limits, out);
    if (primary.succeeded()) {
      recovered_from_backup = false;
      return primary;
    }
  }
  const std::filesystem::path backup = target.string() + ".bak";
  std::error_code error;
  if (!std::filesystem::exists(backup, error)) {
    return primary;
  }
  std::vector<std::uint8_t> backup_buffer;
  FabricOutcome fallback = read_file(backup, backup_buffer);
  if (!fallback.succeeded()) {
    return primary;
  }
  DecodedStore backup_store;
  fallback = decode_store(backup_buffer, limits, backup_store);
  if (!fallback.succeeded()) {
    return primary;
  }
  out = std::move(backup_store);
  recovered_from_backup = true;
  return make_outcome(OutcomeCode::RECOVERED,
                      "primary store was unusable (" + primary.detail +
                          "); recovered from the previous-generation backup");
}

}  // namespace

FabricOutcome FabricEngine::inspect_store_file(const std::string& path,
                                               StoreStatistics& statistics) {
  Limits limits;
  DecodedStore decoded;
  bool recovered = false;
  const FabricOutcome result = read_and_decode(path, limits, decoded, recovered);
  if (!result.succeeded()) {
    // A checksum failure on the primary store is reported as integrity, not as
    // a missing file, so operators can distinguish the two.
    return result;
  }
  statistics.format_version = persistence_format_version;
  statistics.set_count = decoded.sets.size();
  statistics.member_count = 0;
  statistics.revocation_count = 0;
  for (const auto& record : decoded.sets) {
    statistics.member_count += record.members.size();
    if (record.revocation.has_value()) {
      ++statistics.revocation_count;
    }
  }
  statistics.fence_count = decoded.fences.size();
  statistics.epoch = decoded.epoch;
  statistics.authority_generation = decoded.authority_generation;
  statistics.payload_digest = decoded.payload_digest;
  statistics.recovered_from_backup = recovered;
  return make_outcome(OutcomeCode::OK, "inspected store " + path);
}

// ---------------------------------------------------------------------------
// Loading with conservative recovery
// ---------------------------------------------------------------------------

FabricOutcome FabricEngine::load_store(const std::string& path) {
  if (path.empty()) {
    return make_rejection(OutcomeCode::MALFORMED_REQUEST, "load_store requires a file path");
  }
  DecodedStore decoded;
  bool recovered = false;
  const FabricOutcome read = read_and_decode(path, impl_->config.limits, decoded, recovered);
  if (!read.succeeded()) {
    return read;
  }

  std::unique_lock<std::shared_mutex> lock(impl_->mutex);
  const auto next_epoch = decoded.epoch.next();
  if (!next_epoch.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "the stored coordinator epoch is exhausted; a new epoch cannot be "
                          "consumed");
  }
  const auto next_authority = decoded.authority_generation.next();
  if (!next_authority.has_value()) {
    return make_rejection(OutcomeCode::GENERATION_OVERFLOW,
                          "the stored authority generation is exhausted");
  }

  // The load replaces the entire live state. Live authority is never restored
  // from disk: registrations and sessions are dropped, sessions are not
  // reconstructed, and every set loses live currentness.
  impl_->sets.clear();
  impl_->key_index.clear();
  impl_->path_dependents.clear();
  impl_->registrations.clear();
  impl_->fences.clear();
  impl_->snapshot_history.clear();
  impl_->attempts.clear();
  impl_->attempt_index.clear();
  impl_->total_members = 0;
  impl_->current_epoch = *next_epoch;
  impl_->current_authority_generation = *next_authority;

  for (const auto& fence : decoded.fences) {
    FenceRecord record = fence;
    record.epoch = impl_->current_epoch;
    impl_->fences[std::make_pair(record.publisher, record.worker_boot)] = record;
  }

  std::size_t recovered_sets = 0;
  for (auto& record : decoded.sets) {
    if (impl_->key_index.find(record.key) != impl_->key_index.end()) {
      return make_rejection(OutcomeCode::STORE_DUPLICATE_SET,
                            "store contains two sets with the same semantic key " +
                                record.key.render());
    }
    if (impl_->sets.find(record.id) != impl_->sets.end()) {
      return make_rejection(OutcomeCode::STORE_DUPLICATE_SET,
                            "store contains the same set identity more than once: " +
                                record.id.str());
    }
    // Conservative recovery: durable membership description survives. Live
    // currentness, live authority and Path Authority generation currency are
    // never restored from disk.
    for (auto& member : record.members) {
      impl_->bump_member_watermark_locked(member.second);
    }
    impl_->bump_set_watermark_locked(record);
    record.currentness = SetCurrentness::REVALIDATION_REQUIRED;
    record.governing_epoch = impl_->current_epoch;
    record.authority_generation = impl_->current_authority_generation;
    record.usable_member_count = record.recompute_usable_members();

    const MultipathSetId id = record.id;
    const std::size_t member_count = record.members.size();
    impl_->append_history_locked(record, SetEvent::EPOCH_ADVANCE, MembershipCause::RECOVERED,
                                 nullptr, std::nullopt, std::nullopt,
                                 "recovered from durable store at epoch " +
                                     std::to_string(impl_->current_epoch.value()) +
                                     "; live currentness not established");
    impl_->sets.emplace(id, std::move(record));
    impl_->key_index.emplace(impl_->sets.at(id).key, id);
    for (const auto& member : impl_->sets.at(id).members) {
      impl_->index_path_locked(id, member.first);
    }
    impl_->total_members += member_count;
    impl_->capture_snapshot_locked(impl_->sets.at(id));
    ++recovered_sets;
  }

  std::ostringstream detail;
  detail << "loaded " << recovered_sets << " set(s) from " << path << " at epoch "
         << impl_->current_epoch.value() << "; every set reports currentness "
            "REVALIDATION_REQUIRED until revalidation establishes live authority";
  if (recovered) {
    detail << "; primary store was unusable and the previous-generation backup was loaded";
  }
  FabricOutcome outcome = make_outcome(OutcomeCode::RECOVERED, detail.str());
  outcome.authority_generation = impl_->current_authority_generation;
  return outcome;
}

}  // namespace multipath_fabric
