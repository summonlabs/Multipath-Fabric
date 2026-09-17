#include "multipath_fabric/wire.hpp"

#include <array>
#include <limits>

#include "multipath_fabric/version.hpp"

namespace multipath_fabric::wire {
namespace {

constexpr std::size_t kMaxIdLength = 128;
constexpr std::size_t kMaxTextLength = 512;
constexpr std::size_t kMaxDetailLength = 1024;
constexpr std::uint64_t kMaxFrameHardBound = 64ULL * 1024ULL * 1024ULL;

[[nodiscard]] FabricOutcome malformed(std::string detail) {
  return make_rejection(OutcomeCode::MALFORMED_REQUEST, std::move(detail));
}

// Writer helpers report structural failure through ByteWriter::overflowed(), which
// every encoder checks before returning, so their individual results are not
// separately actionable.
void write_optional_id(detail::ByteWriter& writer, bool present, std::string_view value) {
  writer.boolean(present);
  if (present) {
    writer.string(value, kMaxIdLength);
  }
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

bool write_scope(detail::ByteWriter& writer, const AuthorityScope& scope) {
  writer.string(scope.fabric.valid() ? scope.fabric.view() : std::string_view(""), kMaxIdLength);
  writer.string(scope.name_space.valid() ? scope.name_space.view() : std::string_view(""),
                kMaxIdLength);
  const auto count = detail::narrow_u32(scope.set_ids.size());
  if (!count.has_value()) {
    return false;
  }
  writer.u32(*count);
  for (const auto& id : scope.set_ids) {
    writer.string(id.view(), kMaxIdLength);
  }
  return true;
}

[[nodiscard]] bool read_scope(detail::ByteReader& reader, AuthorityScope& scope) {
  const auto fabric = reader.string(kMaxIdLength);
  const auto name_space = reader.string(kMaxIdLength);
  const auto count = reader.u32();
  if (!fabric.has_value() || !name_space.has_value() || !count.has_value()) {
    return false;
  }
  if (*count > 4096U) {
    reader.fail();
    return false;
  }
  if (!fabric->empty()) {
    const auto parsed = FabricId::parse(*fabric);
    if (!parsed.has_value()) {
      reader.fail();
      return false;
    }
    scope.fabric = *parsed;
  }
  if (!name_space->empty()) {
    const auto parsed = MultipathNamespace::parse(*name_space);
    if (!parsed.has_value()) {
      reader.fail();
      return false;
    }
    scope.name_space = *parsed;
  }
  for (std::uint32_t i = 0; i < *count; ++i) {
    const auto value = reader.string(kMaxIdLength);
    if (!value.has_value()) {
      return false;
    }
    const auto parsed = MultipathSetId::parse(*value);
    if (!parsed.has_value()) {
      reader.fail();
      return false;
    }
    scope.set_ids.push_back(*parsed);
  }
  return true;
}

bool write_context(detail::ByteWriter& writer, const MutationContext& context) {
  writer.u64(context.epoch.valid() ? context.epoch.value() : 0);
  writer.string(context.publisher.valid() ? context.publisher.view() : std::string_view(""),
                kMaxIdLength);
  writer.string(context.worker_boot.valid() ? context.worker_boot.view() : std::string_view(""),
                kMaxIdLength);
  writer.string(context.session.valid() ? context.session.view() : std::string_view(""),
                kMaxIdLength);
  writer.string(context.attempt.valid() ? context.attempt.view() : std::string_view(""),
                kMaxIdLength);
  write_optional_id(writer, context.expected_set_generation.has_value(),
                    context.expected_set_generation.has_value()
                        ? std::to_string(context.expected_set_generation->value())
                        : std::string_view(""));
  write_optional_id(writer, context.expected_member_generation.has_value(),
                    context.expected_member_generation.has_value()
                        ? std::to_string(context.expected_member_generation->value())
                        : std::string_view(""));
  return true;
}

[[nodiscard]] std::optional<std::uint64_t> parse_u64(std::string_view text) {
  if (text.empty()) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9') {
      return std::nullopt;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10ULL) {
      return std::nullopt;
    }
    value = value * 10ULL + digit;
  }
  return value;
}

[[nodiscard]] bool read_context(detail::ByteReader& reader, MutationContext& context) {
  const auto epoch = reader.u64();
  const auto publisher = reader.string(kMaxIdLength);
  const auto boot = reader.string(kMaxIdLength);
  const auto session = reader.string(kMaxIdLength);
  const auto attempt = reader.string(kMaxIdLength);
  std::string expected_set;
  std::string expected_member;
  if (!epoch.has_value() || !publisher.has_value() || !boot.has_value() ||
      !session.has_value() || !attempt.has_value()) {
    return false;
  }
  if (!read_optional_id(reader, expected_set) || !read_optional_id(reader, expected_member)) {
    return false;
  }
  if (*epoch != 0) {
    const auto parsed = CoordinatorEpoch::from_value(*epoch);
    if (!parsed.has_value()) {
      reader.fail();
      return false;
    }
    context.epoch = *parsed;
  } else {
    reader.fail();
    return false;
  }
  const auto publisher_id = PublisherId::parse(*publisher);
  const auto boot_id = WorkerBootId::parse(*boot);
  const auto session_id = SessionId::parse(*session);
  const auto attempt_id = MutationAttemptId::parse(*attempt);
  if (!publisher_id.has_value() || !boot_id.has_value() || !session_id.has_value() ||
      !attempt_id.has_value()) {
    reader.fail();
    return false;
  }
  context.publisher = *publisher_id;
  context.worker_boot = *boot_id;
  context.session = *session_id;
  context.attempt = *attempt_id;
  if (!expected_set.empty()) {
    const auto value = parse_u64(expected_set);
    if (!value.has_value()) {
      reader.fail();
      return false;
    }
    const auto generation = MultipathSetGeneration::from_value(*value);
    if (!generation.has_value()) {
      reader.fail();
      return false;
    }
    context.expected_set_generation = *generation;
  }
  if (!expected_member.empty()) {
    const auto value = parse_u64(expected_member);
    if (!value.has_value()) {
      reader.fail();
      return false;
    }
    const auto generation = MultipathMemberGeneration::from_value(*value);
    if (!generation.has_value()) {
      reader.fail();
      return false;
    }
    context.expected_member_generation = *generation;
  }
  return true;
}

bool write_key(detail::ByteWriter& writer, const SetKey& key) {
  writer.string(key.fabric.valid() ? key.fabric.view() : std::string_view(""), kMaxIdLength);
  writer.string(key.name_space.valid() ? key.name_space.view() : std::string_view(""),
                kMaxIdLength);
  writer.string(key.name.valid() ? key.name.view() : std::string_view(""), kMaxIdLength);
  return true;
}

[[nodiscard]] bool read_key(detail::ByteReader& reader, SetKey& key) {
  const auto fabric = reader.string(kMaxIdLength);
  const auto name_space = reader.string(kMaxIdLength);
  const auto name = reader.string(kMaxIdLength);
  if (!fabric.has_value() || !name_space.has_value() || !name.has_value()) {
    return false;
  }
  const auto fabric_id = FabricId::parse(*fabric);
  const auto namespace_id = MultipathNamespace::parse(*name_space);
  const auto name_id = MultipathSetName::parse(*name);
  if (!fabric_id.has_value() || !namespace_id.has_value() || !name_id.has_value()) {
    reader.fail();
    return false;
  }
  key.fabric = *fabric_id;
  key.name_space = *namespace_id;
  key.name = *name_id;
  return true;
}

}  // namespace

bool valid_message_id(std::uint16_t raw) noexcept {
  return raw >= message_id_min && raw <= message_id_max;
}

std::string_view to_string(MessageId id) noexcept {
  switch (id) {
    case MessageId::HELLO: return "HELLO";
    case MessageId::HELLO_ACK: return "HELLO_ACK";
    case MessageId::REGISTER_PUBLISHER: return "REGISTER_PUBLISHER";
    case MessageId::CREATE_SET: return "CREATE_SET";
    case MessageId::ADD_MEMBER: return "ADD_MEMBER";
    case MessageId::REMOVE_MEMBER: return "REMOVE_MEMBER";
    case MessageId::REVALIDATE_MEMBER: return "REVALIDATE_MEMBER";
    case MessageId::REVALIDATE_SET: return "REVALIDATE_SET";
    case MessageId::REVOKE_SET: return "REVOKE_SET";
    case MessageId::RETIRE_SET: return "RETIRE_SET";
    case MessageId::QUERY_SET: return "QUERY_SET";
    case MessageId::SNAPSHOT_REQUEST: return "SNAPSHOT_REQUEST";
    case MessageId::SNAPSHOT_RESPONSE: return "SNAPSHOT_RESPONSE";
    case MessageId::FENCE_NOTICE: return "FENCE_NOTICE";
    case MessageId::RESULT: return "RESULT";
    case MessageId::ERROR: return "ERROR";
    case MessageId::REPLACE_MEMBER: return "REPLACE_MEMBER";
    case MessageId::SET_MINIMUM: return "SET_MINIMUM";
    case MessageId::SET_ADMIN_ENABLE: return "SET_ADMIN_ENABLE";
    case MessageId::SET_ADMIN_DISABLE: return "SET_ADMIN_DISABLE";
    case MessageId::MEMBER_ADMIN_ENABLE: return "MEMBER_ADMIN_ENABLE";
    case MessageId::MEMBER_ADMIN_DISABLE: return "MEMBER_ADMIN_DISABLE";
    case MessageId::EPOCH_ADVANCE: return "EPOCH_ADVANCE";
    case MessageId::LIST_SETS: return "LIST_SETS";
    case MessageId::ADVANCE_SET_STATE: return "ADVANCE_SET_STATE";
    case MessageId::APPLY_PATH_AUTHORITY: return "APPLY_PATH_AUTHORITY";
    case MessageId::REFRESH_PATH: return "REFRESH_PATH";
    case MessageId::ADD_MEMBERS: return "ADD_MEMBERS";
    case MessageId::WITHDRAW_MEMBER: return "WITHDRAW_MEMBER";
    case MessageId::SET_CONDITIONAL_POLICY: return "SET_CONDITIONAL_POLICY";
    case MessageId::SUPERSEDE_SET: return "SUPERSEDE_SET";
    case MessageId::SHUTDOWN: return "SHUTDOWN";
    case MessageId::EXPLAIN_SET: return "EXPLAIN_SET";
    case MessageId::DECLARE_PATH_AUTHORITY: return "DECLARE_PATH_AUTHORITY";
  }
  return "<invalid-message-id>";
}

std::optional<MessageId> parse_message_id(std::string_view text) noexcept {
  for (std::uint16_t raw = message_id_min; raw <= message_id_max; ++raw) {
    const auto candidate = static_cast<MessageId>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool valid_set_state_action(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 3; }

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

FabricOutcome encode_frame(MessageId id, const std::vector<std::uint8_t>& payload,
                           std::uint64_t max_frame_bytes, std::vector<std::uint8_t>& out) {
  const std::uint64_t bound =
      max_frame_bytes == 0 ? kMaxFrameHardBound
                           : (max_frame_bytes < kMaxFrameHardBound ? max_frame_bytes
                                                                   : kMaxFrameHardBound);
  if (payload.size() > bound) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "frame payload of " + std::to_string(payload.size()) +
                              " bytes exceeds max_frame_bytes " + std::to_string(bound));
  }
  detail::ByteWriter header(frame_header_size);
  header.u32(frame_magic);
  header.u16(wire_protocol_version);
  header.u16(static_cast<std::uint16_t>(id));
  const auto length = detail::narrow_u32(payload.size());
  if (!length.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "frame payload length is not representable");
  }
  header.u32(*length);
  header.u32(0);
  if (header.overflowed() || header.size() != frame_integrity_offset) {
    return make_rejection(OutcomeCode::INTERNAL_ERROR, "frame header encoding failed");
  }
  detail::DigestBuilder integrity;
  integrity.absorb_bytes(std::string_view(
      reinterpret_cast<const char*>(header.buffer().data()), header.buffer().size()));
  integrity.absorb_bytes(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                          payload.size()));
  const std::uint64_t check = integrity.finish().high;

  out.clear();
  out.reserve(frame_header_size + payload.size());
  out.insert(out.end(), header.buffer().begin(), header.buffer().end());
  detail::ByteWriter trailer(16);
  trailer.u64(check);
  out.insert(out.end(), trailer.buffer().begin(), trailer.buffer().end());
  out.insert(out.end(), payload.begin(), payload.end());
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_header(const std::uint8_t* header, std::size_t header_size,
                            std::uint64_t max_frame_bytes, MessageId& id,
                            std::uint32_t& payload_length) {
  if (header == nullptr || header_size < frame_integrity_offset) {
    return make_rejection(OutcomeCode::FRAMING_ERROR,
                          "frame header buffer holds " + std::to_string(header_size) +
                              " byte(s); " + std::to_string(frame_integrity_offset) +
                              " are required before the frame can be decoded");
  }
  detail::ByteReader reader(header, frame_integrity_offset);
  const auto magic = reader.u32();
  const auto version = reader.u16();
  const auto message = reader.u16();
  const auto length = reader.u32();
  const auto flags = reader.u32();
  if (!magic.has_value() || !version.has_value() || !message.has_value() ||
      !length.has_value() || !flags.has_value()) {
    return make_rejection(OutcomeCode::FRAMING_ERROR, "frame header is truncated");
  }
  if (*magic != frame_magic) {
    return make_rejection(OutcomeCode::FRAMING_ERROR, "frame magic does not match");
  }
  if (*version != wire_protocol_version) {
    return make_rejection(OutcomeCode::UNSUPPORTED_WIRE_VERSION,
                          "wire version " + std::to_string(*version) +
                              " is not supported; this build speaks version " +
                              std::to_string(wire_protocol_version));
  }
  if (*flags != 0) {
    return make_rejection(OutcomeCode::FRAMING_ERROR, "frame flags must be zero");
  }
  if (!valid_message_id(*message)) {
    return make_rejection(OutcomeCode::FRAMING_ERROR,
                          "frame carries an unknown message id " + std::to_string(*message));
  }
  const std::uint64_t bound =
      max_frame_bytes == 0 ? kMaxFrameHardBound
                           : (max_frame_bytes < kMaxFrameHardBound ? max_frame_bytes
                                                                   : kMaxFrameHardBound);
  if (*length > bound) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "frame declares " + std::to_string(*length) +
                              " payload bytes which exceeds max_frame_bytes " +
                              std::to_string(bound));
  }
  id = static_cast<MessageId>(*message);
  payload_length = *length;
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome verify_integrity(const std::uint8_t* header, std::size_t header_size,
                                   const std::vector<std::uint8_t>& payload) {
  if (header == nullptr || header_size < frame_header_size) {
    return make_rejection(OutcomeCode::FRAMING_ERROR,
                          "frame header buffer holds " + std::to_string(header_size) +
                              " byte(s); " + std::to_string(frame_header_size) +
                              " are required to verify the integrity field");
  }
  detail::ByteReader trailer(header + frame_integrity_offset,
                             frame_header_size - frame_integrity_offset);
  const auto stored = trailer.u64();
  if (!stored.has_value()) {
    return make_rejection(OutcomeCode::FRAMING_ERROR, "frame integrity field is truncated");
  }
  detail::DigestBuilder integrity;
  integrity.absorb_bytes(std::string_view(reinterpret_cast<const char*>(header),
                                          frame_integrity_offset));
  integrity.absorb_bytes(std::string_view(reinterpret_cast<const char*>(payload.data()),
                                          payload.size()));
  if (integrity.finish().high != *stored) {
    return make_rejection(OutcomeCode::INTEGRITY_ERROR,
                          "frame integrity check failed over the semantic header and payload");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

// ---------------------------------------------------------------------------
// Outcome codec
// ---------------------------------------------------------------------------

FabricOutcome encode_outcome(detail::ByteWriter& writer, const FabricOutcome& outcome) {
  writer.u16(static_cast<std::uint16_t>(outcome.code));
  writer.u8(static_cast<std::uint8_t>(outcome.stage));
  std::uint8_t mask = 0;
  if (outcome.set_id.has_value()) mask |= 0x01U;
  if (outcome.member_id.has_value()) mask |= 0x02U;
  if (outcome.path_id.has_value()) mask |= 0x04U;
  if (outcome.set_generation.has_value()) mask |= 0x08U;
  if (outcome.membership_generation.has_value()) mask |= 0x10U;
  if (outcome.member_generation.has_value()) mask |= 0x20U;
  if (outcome.authority_generation.has_value()) mask |= 0x40U;
  if (outcome.lifecycle.has_value()) mask |= 0x80U;
  writer.u8(mask);
  std::uint8_t mask2 = 0;
  if (outcome.currentness.has_value()) mask2 |= 0x01U;
  if (outcome.usable_members.has_value()) mask2 |= 0x02U;
  if (outcome.minimum_usable_members.has_value()) mask2 |= 0x04U;
  if (outcome.digest.has_value()) mask2 |= 0x08U;
  writer.u8(mask2);
  if (outcome.set_id.has_value()) writer.string(outcome.set_id->view(), kMaxIdLength);
  if (outcome.member_id.has_value()) writer.string(outcome.member_id->view(), kMaxIdLength);
  if (outcome.path_id.has_value()) writer.string(outcome.path_id->view(), kMaxIdLength);
  if (outcome.set_generation.has_value()) writer.u64(outcome.set_generation->value());
  if (outcome.membership_generation.has_value()) writer.u64(outcome.membership_generation->value());
  if (outcome.member_generation.has_value()) writer.u64(outcome.member_generation->value());
  if (outcome.authority_generation.has_value()) {
    writer.u64(outcome.authority_generation->value());
  }
  if (outcome.lifecycle.has_value()) writer.u8(static_cast<std::uint8_t>(*outcome.lifecycle));
  if (outcome.currentness.has_value()) writer.u8(static_cast<std::uint8_t>(*outcome.currentness));
  if (outcome.usable_members.has_value()) writer.u64(*outcome.usable_members);
  if (outcome.minimum_usable_members.has_value()) writer.u64(*outcome.minimum_usable_members);
  if (outcome.digest.has_value()) {
    writer.u64(outcome.digest->high);
    writer.u64(outcome.digest->low);
  }
  writer.string(outcome.detail, kMaxDetailLength);
  if (writer.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "outcome encoding exceeded its bound");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_outcome(detail::ByteReader& reader, FabricOutcome& outcome) {
  const auto code = reader.u16();
  const auto stage = reader.u8();
  const auto mask = reader.u8();
  const auto mask2 = reader.u8();
  if (!code.has_value() || !stage.has_value() || !mask.has_value() || !mask2.has_value()) {
    return make_rejection(OutcomeCode::FRAMING_ERROR, "result payload header is truncated");
  }
  if (!valid_outcome_code(*code)) {
    return make_rejection(OutcomeCode::FRAMING_ERROR,
                          "result carries an unknown outcome code " + std::to_string(*code));
  }
  if (*stage > static_cast<std::uint8_t>(RejectionStage::COMMIT)) {
    return make_rejection(OutcomeCode::FRAMING_ERROR,
                          "result carries an unknown rejection stage");
  }
  static_cast<void>(mask2);
  outcome = FabricOutcome{};
  outcome.code = static_cast<OutcomeCode>(*code);
  outcome.stage = static_cast<RejectionStage>(*stage);
  if ((*mask & 0x01U) != 0) {
    const auto value = reader.string(kMaxIdLength);
    if (!value.has_value()) return malformed("result set identity is truncated");
    const auto parsed = MultipathSetId::parse(*value);
    if (!parsed.has_value()) return malformed("result carries an invalid set identity");
    outcome.set_id = *parsed;
  }
  if ((*mask & 0x02U) != 0) {
    const auto value = reader.string(kMaxIdLength);
    if (!value.has_value()) return malformed("result member identity is truncated");
    const auto parsed = MultipathMemberId::parse(*value);
    if (!parsed.has_value()) return malformed("result carries an invalid member identity");
    outcome.member_id = *parsed;
  }
  if ((*mask & 0x04U) != 0) {
    const auto value = reader.string(kMaxIdLength);
    if (!value.has_value()) return malformed("result path identity is truncated");
    const auto parsed = PathId::parse(*value);
    if (!parsed.has_value()) return malformed("result carries an invalid path identity");
    outcome.path_id = *parsed;
  }
  if ((*mask & 0x08U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result set generation is truncated");
    const auto parsed = MultipathSetGeneration::from_value(*value);
    if (!parsed.has_value()) return malformed("result carries an impossible set generation");
    outcome.set_generation = *parsed;
  }
  if ((*mask & 0x10U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result membership generation is truncated");
    const auto parsed = MembershipGeneration::from_value(*value);
    if (!parsed.has_value()) return malformed("result carries an impossible membership generation");
    outcome.membership_generation = *parsed;
  }
  if ((*mask & 0x20U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result member generation is truncated");
    const auto parsed = MultipathMemberGeneration::from_value(*value);
    if (!parsed.has_value()) return malformed("result carries an impossible member generation");
    outcome.member_generation = *parsed;
  }
  if ((*mask & 0x40U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result authority generation is truncated");
    const auto parsed = MultipathAuthorityGeneration::from_value(*value);
    if (!parsed.has_value()) {
      return malformed("result carries an impossible authority generation");
    }
    outcome.authority_generation = *parsed;
  }
  if ((*mask & 0x80U) != 0) {
    const auto value = reader.u8();
    if (!value.has_value()) return malformed("result lifecycle is truncated");
    if (!valid_set_lifecycle(*value)) return malformed("result carries a malformed lifecycle");
    outcome.lifecycle = static_cast<SetLifecycle>(*value);
  }
  if ((*mask2 & 0x01U) != 0) {
    const auto value = reader.u8();
    if (!value.has_value()) return malformed("result currentness is truncated");
    if (!valid_set_currentness(*value)) return malformed("result carries a malformed currentness");
    outcome.currentness = static_cast<SetCurrentness>(*value);
  }
  if ((*mask2 & 0x02U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result usable count is truncated");
    outcome.usable_members = *value;
  }
  if ((*mask2 & 0x04U) != 0) {
    const auto value = reader.u64();
    if (!value.has_value()) return malformed("result minimum requirement is truncated");
    outcome.minimum_usable_members = *value;
  }
  if ((*mask2 & 0x08U) != 0) {
    const auto high = reader.u64();
    const auto low = reader.u64();
    if (!high.has_value() || !low.has_value()) return malformed("result digest is truncated");
    detail::Digest128 digest;
    digest.high = *high;
    digest.low = *low;
    outcome.digest = digest;
  }
  const auto detail = reader.string(kMaxDetailLength);
  if (!detail.has_value()) return malformed("result detail is truncated");
  outcome.detail = *detail;
  return make_outcome(OutcomeCode::OK, std::string());
}

// ---------------------------------------------------------------------------
// Snapshot codec
// ---------------------------------------------------------------------------

FabricOutcome encode_snapshot(detail::ByteWriter& writer, const SetSnapshot& snapshot) {
  writer.string(snapshot.snapshot_id.view(), kMaxIdLength);
  writer.string(snapshot.set_id.view(), kMaxIdLength);
  write_key(writer, snapshot.key);
  writer.u64(snapshot.generation.value());
  writer.u64(snapshot.membership_generation.value());
  writer.u64(snapshot.authority_generation.value());
  writer.u8(static_cast<std::uint8_t>(snapshot.lifecycle));
  writer.u8(static_cast<std::uint8_t>(snapshot.currentness));
  writer.u8(static_cast<std::uint8_t>(snapshot.readiness));
  writer.boolean(snapshot.admin_enabled);
  writer.u64(snapshot.minimum_usable_members);
  writer.boolean(snapshot.conditional_authority_permitted);
  writer.u64(snapshot.usable_member_count);
  writer.u64(snapshot.member_count);
  writer.u64(snapshot.governing_epoch.value());
  writer.u64(snapshot.digest.high);
  writer.u64(snapshot.digest.low);
  writer.boolean(snapshot.superseded_by.has_value());
  if (snapshot.superseded_by.has_value()) {
    writer.string(snapshot.superseded_by->view(), kMaxIdLength);
  }
  writer.boolean(snapshot.supersedes.has_value());
  if (snapshot.supersedes.has_value()) {
    writer.string(snapshot.supersedes->view(), kMaxIdLength);
  }
  writer.boolean(snapshot.revocation.has_value());
  if (snapshot.revocation.has_value()) {
    writer.u8(static_cast<std::uint8_t>(snapshot.revocation->reason));
    writer.string(snapshot.revocation->detail, kMaxTextLength);
    writer.u64(snapshot.revocation->generation.value());
    writer.u64(snapshot.revocation->authority_generation.value());
    writer.u64(snapshot.revocation->epoch.value());
    writer.string(snapshot.revocation->publisher.view(), kMaxIdLength);
  }
  writer.string(snapshot.withdrawal_reason, kMaxTextLength);
  writer.string(snapshot.provenance.publisher.valid() ? snapshot.provenance.publisher.view()
                                                      : std::string_view(""),
                kMaxIdLength);
  writer.string(snapshot.provenance.worker_boot.valid() ? snapshot.provenance.worker_boot.view()
                                                        : std::string_view(""),
                kMaxIdLength);
  writer.u64(snapshot.provenance.epoch.valid() ? snapshot.provenance.epoch.value() : 1);
  writer.string(snapshot.provenance.attempt.valid() ? snapshot.provenance.attempt.view()
                                                    : std::string_view(""),
                kMaxIdLength);
  writer.u64(snapshot.provenance.set_generation.valid()
                 ? snapshot.provenance.set_generation.value()
                 : 1);
  writer.u8(static_cast<std::uint8_t>(snapshot.provenance.cause));
  const auto history_count = detail::narrow_u32(snapshot.history.size());
  if (!history_count.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT,
                          "snapshot history count is not representable");
  }
  writer.u32(*history_count);
  for (const auto& entry : snapshot.history) {
    writer.u64(entry.set_generation.value());
    writer.u8(static_cast<std::uint8_t>(entry.event));
    writer.u8(static_cast<std::uint8_t>(entry.cause));
    writer.string(entry.publisher.valid() ? entry.publisher.view() : std::string_view(""),
                  kMaxIdLength);
    writer.u64(entry.epoch.valid() ? entry.epoch.value() : 1);
    writer.boolean(entry.member_id.has_value());
    if (entry.member_id.has_value()) {
      writer.string(entry.member_id->view(), kMaxIdLength);
    }
    writer.boolean(entry.path_id.has_value());
    if (entry.path_id.has_value()) {
      writer.string(entry.path_id->view(), kMaxIdLength);
    }
    writer.string(entry.summary, kMaxDetailLength);
  }
  const auto member_count = detail::narrow_u32(snapshot.members.size());
  if (!member_count.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "snapshot member count is not representable");
  }
  writer.u32(*member_count);
  for (const auto& member : snapshot.members) {
    writer.string(member.id.view(), kMaxIdLength);
    writer.string(member.path_id.view(), kMaxIdLength);
    writer.u64(member.bound_authority_generation.value());
    writer.u64(member.generation.value());
    writer.u8(static_cast<std::uint8_t>(member.lifecycle));
    writer.u8(static_cast<std::uint8_t>(member.currentness));
    writer.boolean(member.admin_enabled);
    writer.boolean(member.usable);
    writer.u64(member.invalidation_watermark.value());
    writer.u32(member.pending_revalidations);
    writer.boolean(member.predecessor.has_value());
    if (member.predecessor.has_value()) {
      writer.string(member.predecessor->view(), kMaxIdLength);
    }
    writer.boolean(member.successor.has_value());
    if (member.successor.has_value()) {
      writer.string(member.successor->view(), kMaxIdLength);
    }
    writer.string(member.provenance.publisher.valid() ? member.provenance.publisher.view()
                                                      : std::string_view(""),
                  kMaxIdLength);
    writer.string(member.provenance.worker_boot.valid() ? member.provenance.worker_boot.view()
                                                        : std::string_view(""),
                  kMaxIdLength);
    writer.u64(member.provenance.epoch.valid() ? member.provenance.epoch.value() : 0);
    writer.string(member.provenance.attempt.valid() ? member.provenance.attempt.view()
                                                    : std::string_view(""),
                  kMaxIdLength);
    writer.u64(member.provenance.set_generation.valid()
                   ? member.provenance.set_generation.value()
                   : 1);
    writer.u8(static_cast<std::uint8_t>(member.provenance.cause));
  }
  if (writer.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "snapshot encoding exceeded its bound");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_snapshot(detail::ByteReader& reader, SetSnapshot& snapshot) {
  const auto snapshot_id = reader.string(kMaxIdLength);
  const auto set_id = reader.string(kMaxIdLength);
  if (!snapshot_id.has_value() || !set_id.has_value()) {
    return malformed("snapshot identity is truncated");
  }
  const auto snapshot_id_value = SnapshotId::parse(*snapshot_id);
  const auto set_id_value = MultipathSetId::parse(*set_id);
  if (!snapshot_id_value.has_value() || !set_id_value.has_value()) {
    return malformed("snapshot carries an invalid identity");
  }
  snapshot = SetSnapshot{};
  snapshot.snapshot_id = *snapshot_id_value;
  snapshot.set_id = *set_id_value;
  if (!read_key(reader, snapshot.key)) {
    return malformed("snapshot set key is truncated or malformed");
  }
  const auto generation = reader.u64();
  const auto membership_generation = reader.u64();
  const auto authority_generation = reader.u64();
  const auto lifecycle = reader.u8();
  const auto currentness = reader.u8();
  const auto readiness = reader.u8();
  const auto admin_enabled = reader.boolean();
  const auto minimum = reader.u64();
  const auto conditional = reader.boolean();
  const auto usable = reader.u64();
  const auto member_count = reader.u64();
  const auto governing_epoch = reader.u64();
  const auto digest_high = reader.u64();
  const auto digest_low = reader.u64();
  if (!generation.has_value() || !membership_generation.has_value() ||
      !authority_generation.has_value() || !lifecycle.has_value() || !currentness.has_value() ||
      !readiness.has_value() || !admin_enabled.has_value() || !minimum.has_value() ||
      !conditional.has_value() || !usable.has_value() || !member_count.has_value() ||
      !governing_epoch.has_value() || !digest_high.has_value() || !digest_low.has_value()) {
    return malformed("snapshot scalar block is truncated");
  }
  const auto generation_value = MultipathSetGeneration::from_value(*generation);
  const auto membership_value = MembershipGeneration::from_value(*membership_generation);
  const auto authority_value = MultipathAuthorityGeneration::from_value(*authority_generation);
  const auto epoch_value = CoordinatorEpoch::from_value(*governing_epoch);
  if (!generation_value.has_value() || !membership_value.has_value() ||
      !authority_value.has_value() || !epoch_value.has_value()) {
    return malformed("snapshot carries an impossible generation");
  }
  if (!valid_set_lifecycle(*lifecycle) || !valid_set_currentness(*currentness) ||
      !valid_route_readiness(*readiness)) {
    return malformed("snapshot carries a malformed enumerator");
  }
  snapshot.generation = *generation_value;
  snapshot.membership_generation = *membership_value;
  snapshot.authority_generation = *authority_value;
  snapshot.lifecycle = static_cast<SetLifecycle>(*lifecycle);
  snapshot.currentness = static_cast<SetCurrentness>(*currentness);
  snapshot.readiness = static_cast<RouteReadiness>(*readiness);
  snapshot.admin_enabled = *admin_enabled;
  snapshot.minimum_usable_members = *minimum;
  snapshot.conditional_authority_permitted = *conditional;
  snapshot.usable_member_count = *usable;
  snapshot.member_count = *member_count;
  snapshot.governing_epoch = *epoch_value;
  snapshot.digest.high = *digest_high;
  snapshot.digest.low = *digest_low;
  if (*member_count > 1000000ULL) {
    return malformed("snapshot declares an absurd member count");
  }
  std::string optional;
  if (!read_optional_id(reader, optional)) {
    return malformed("snapshot supersession field is truncated");
  }
  if (!optional.empty()) {
    const auto parsed = MultipathSetId::parse(optional);
    if (!parsed.has_value()) return malformed("snapshot carries an invalid superseded_by");
    snapshot.superseded_by = *parsed;
  }
  if (!read_optional_id(reader, optional)) {
    return malformed("snapshot predecessor field is truncated");
  }
  if (!optional.empty()) {
    const auto parsed = MultipathSetId::parse(optional);
    if (!parsed.has_value()) return malformed("snapshot carries an invalid supersedes");
    snapshot.supersedes = *parsed;
  }
  const auto has_revocation = reader.boolean();
  if (!has_revocation.has_value()) {
    return malformed("snapshot revocation flag is truncated");
  }
  if (*has_revocation) {
    const auto reason = reader.u8();
    const auto detail = reader.string(kMaxTextLength);
    const auto revocation_generation = reader.u64();
    const auto revocation_authority = reader.u64();
    const auto revocation_epoch = reader.u64();
    const auto publisher = reader.string(kMaxIdLength);
    if (!reason.has_value() || !detail.has_value() || !revocation_generation.has_value() ||
        !revocation_authority.has_value() || !revocation_epoch.has_value() ||
        !publisher.has_value()) {
      return malformed("snapshot revocation block is truncated");
    }
    if (!valid_revocation_reason(*reason)) {
      return malformed("snapshot revocation carries a malformed reason");
    }
    const auto generation_parsed = MultipathSetGeneration::from_value(*revocation_generation);
    const auto authority_parsed = MultipathAuthorityGeneration::from_value(*revocation_authority);
    const auto epoch_parsed = CoordinatorEpoch::from_value(*revocation_epoch);
    const auto publisher_parsed = PublisherId::parse(*publisher);
    if (!generation_parsed.has_value() || !authority_parsed.has_value() ||
        !epoch_parsed.has_value() || !publisher_parsed.has_value()) {
      return malformed("snapshot revocation carries an impossible generation");
    }
    RevocationRecord revocation;
    revocation.set_id = snapshot.set_id;
    revocation.reason = static_cast<RevocationReason>(*reason);
    revocation.detail = *detail;
    revocation.generation = *generation_parsed;
    revocation.authority_generation = *authority_parsed;
    revocation.epoch = *epoch_parsed;
    revocation.publisher = *publisher_parsed;
    snapshot.revocation = std::move(revocation);
  }
  const auto withdrawal = reader.string(kMaxTextLength);
  if (!withdrawal.has_value()) {
    return malformed("snapshot withdrawal reason is truncated");
  }
  snapshot.withdrawal_reason = *withdrawal;
  {
    const auto publisher = reader.string(kMaxIdLength);
    const auto boot = reader.string(kMaxIdLength);
    const auto epoch = reader.u64();
    const auto attempt = reader.string(kMaxIdLength);
    const auto provenance_generation = reader.u64();
    const auto provenance_cause = reader.u8();
    if (!publisher.has_value() || !boot.has_value() || !epoch.has_value() ||
        !attempt.has_value() || !provenance_generation.has_value() ||
        !provenance_cause.has_value()) {
      return malformed("snapshot set provenance is truncated");
    }
    if (!valid_membership_cause(*provenance_cause)) {
      return malformed("snapshot set provenance carries a malformed cause");
    }
    if (!publisher->empty()) {
      const auto parsed = PublisherId::parse(*publisher);
      if (!parsed.has_value()) return malformed("snapshot set provenance publisher is invalid");
      snapshot.provenance.publisher = *parsed;
    }
    if (!boot->empty()) {
      const auto parsed = WorkerBootId::parse(*boot);
      if (!parsed.has_value()) return malformed("snapshot set provenance boot is invalid");
      snapshot.provenance.worker_boot = *parsed;
    }
    if (!attempt->empty()) {
      const auto parsed = MutationAttemptId::parse(*attempt);
      if (!parsed.has_value()) return malformed("snapshot set provenance attempt is invalid");
      snapshot.provenance.attempt = *parsed;
    }
    if (*epoch == 0) {
      return malformed("snapshot set provenance carries an impossible epoch");
    }
    const auto provenance_epoch = CoordinatorEpoch::from_value(*epoch);
    if (!provenance_epoch.has_value()) {
      return malformed("snapshot set provenance carries an impossible epoch");
    }
    snapshot.provenance.epoch = *provenance_epoch;
    if (*provenance_generation != 0) {
      const auto parsed = MultipathSetGeneration::from_value(*provenance_generation);
      if (!parsed.has_value()) {
        return malformed("snapshot set provenance carries an impossible generation");
      }
      snapshot.provenance.set_generation = *parsed;
    }
    snapshot.provenance.cause = static_cast<MembershipCause>(*provenance_cause);
  }
  const auto history_count = reader.u32();
  if (!history_count.has_value()) {
    return malformed("snapshot history count is truncated");
  }
  if (*history_count > 100000U) {
    return malformed("snapshot declares an absurd history count");
  }
  snapshot.history.reserve(*history_count);
  for (std::uint32_t i = 0; i < *history_count; ++i) {
    detail::HistoryEntry entry;
    const auto entry_generation = reader.u64();
    const auto entry_event = reader.u8();
    const auto entry_cause = reader.u8();
    const auto entry_publisher = reader.string(kMaxIdLength);
    const auto entry_epoch = reader.u64();
    std::string entry_member;
    std::string entry_path;
    if (!entry_generation.has_value() || !entry_event.has_value() ||
        !entry_cause.has_value() || !entry_publisher.has_value() ||
        !entry_epoch.has_value()) {
      return malformed("snapshot history entry is truncated");
    }
    if (!read_optional_id(reader, entry_member) || !read_optional_id(reader, entry_path)) {
      return malformed("snapshot history identity is truncated");
    }
    const auto entry_summary = reader.string(kMaxDetailLength);
    if (!entry_summary.has_value()) {
      return malformed("snapshot history summary is truncated");
    }
    if (!valid_set_event(*entry_event) || !valid_membership_cause(*entry_cause)) {
      return malformed("snapshot history entry carries a malformed enumerator");
    }
    const auto entry_generation_value = MultipathSetGeneration::from_value(*entry_generation);
    const auto entry_epoch_value = CoordinatorEpoch::from_value(*entry_epoch);
    if (!entry_generation_value.has_value() || !entry_epoch_value.has_value()) {
      return malformed("snapshot history entry carries an impossible generation");
    }
    if (!entry_publisher->empty()) {
      const auto parsed = PublisherId::parse(*entry_publisher);
      if (!parsed.has_value()) {
        return malformed("snapshot history publisher is invalid");
      }
      entry.publisher = *parsed;
    }
    if (!entry_member.empty()) {
      const auto parsed = MultipathMemberId::parse(entry_member);
      if (!parsed.has_value()) {
        return malformed("snapshot history member identity is invalid");
      }
      entry.member_id = *parsed;
    }
    if (!entry_path.empty()) {
      const auto parsed = PathId::parse(entry_path);
      if (!parsed.has_value()) {
        return malformed("snapshot history path identity is invalid");
      }
      entry.path_id = *parsed;
    }
    entry.set_generation = *entry_generation_value;
    entry.event = static_cast<SetEvent>(*entry_event);
    entry.cause = static_cast<MembershipCause>(*entry_cause);
    entry.epoch = *entry_epoch_value;
    entry.summary = *entry_summary;
    snapshot.history.push_back(std::move(entry));
  }
  const auto count = reader.u32();
  if (!count.has_value()) {
    return malformed("snapshot member count is truncated");
  }
  if (*count > 1000000U) {
    return malformed("snapshot declares an absurd member count");
  }
  snapshot.members.reserve(*count);
  for (std::uint32_t i = 0; i < *count; ++i) {
    MemberSnapshot member;
    const auto id = reader.string(kMaxIdLength);
    const auto path = reader.string(kMaxIdLength);
    const auto bound = reader.u64();
    const auto member_generation = reader.u64();
    const auto member_lifecycle = reader.u8();
    const auto member_currentness = reader.u8();
    const auto member_admin = reader.boolean();
    const auto member_usable = reader.boolean();
    const auto watermark = reader.u64();
    const auto pending = reader.u32();
    if (!id.has_value() || !path.has_value() || !bound.has_value() ||
        !member_generation.has_value() || !member_lifecycle.has_value() ||
        !member_currentness.has_value() || !member_admin.has_value() ||
        !member_usable.has_value() || !watermark.has_value() || !pending.has_value()) {
      return malformed("snapshot member block is truncated");
    }
    const auto id_value = MultipathMemberId::parse(*id);
    const auto path_value = PathId::parse(*path);
    const auto bound_value = PathAuthorityGeneration::from_value(*bound);
    const auto member_generation_value = MultipathMemberGeneration::from_value(*member_generation);
    if (!id_value.has_value() || !path_value.has_value() || !bound_value.has_value() ||
        !member_generation_value.has_value()) {
      return malformed("snapshot member carries an invalid identity or generation");
    }
    if (!valid_member_lifecycle(*member_lifecycle) ||
        !valid_member_currentness(*member_currentness)) {
      return malformed("snapshot member carries a malformed enumerator");
    }
    member.id = *id_value;
    member.path_id = *path_value;
    member.bound_authority_generation = *bound_value;
    member.generation = *member_generation_value;
    member.lifecycle = static_cast<MemberLifecycle>(*member_lifecycle);
    member.currentness = static_cast<MemberCurrentness>(*member_currentness);
    member.admin_enabled = *member_admin;
    member.usable = *member_usable;
    member.invalidation_watermark = Watermark(*watermark);
    member.pending_revalidations = *pending;
    if (!read_optional_id(reader, optional)) {
      return malformed("snapshot member predecessor is truncated");
    }
    if (!optional.empty()) {
      const auto parsed = MultipathMemberId::parse(optional);
      if (!parsed.has_value()) return malformed("snapshot member predecessor is invalid");
      member.predecessor = *parsed;
    }
    if (!read_optional_id(reader, optional)) {
      return malformed("snapshot member successor is truncated");
    }
    if (!optional.empty()) {
      const auto parsed = MultipathMemberId::parse(optional);
      if (!parsed.has_value()) return malformed("snapshot member successor is invalid");
      member.successor = *parsed;
    }
    const auto publisher = reader.string(kMaxIdLength);
    const auto boot = reader.string(kMaxIdLength);
    const auto epoch = reader.u64();
    const auto attempt = reader.string(kMaxIdLength);
    const auto provenance_generation = reader.u64();
    const auto provenance_cause = reader.u8();
    if (!publisher.has_value() || !boot.has_value() || !epoch.has_value() ||
        !attempt.has_value() || !provenance_generation.has_value() ||
        !provenance_cause.has_value()) {
      return malformed("snapshot member provenance is truncated");
    }
    if (!valid_membership_cause(*provenance_cause)) {
      return malformed("snapshot member provenance carries a malformed cause");
    }
    member.provenance.cause = static_cast<MembershipCause>(*provenance_cause);
    if (*provenance_generation != 0) {
      const auto parsed = MultipathSetGeneration::from_value(*provenance_generation);
      if (!parsed.has_value()) {
        return malformed("snapshot member provenance carries an impossible generation");
      }
      member.provenance.set_generation = *parsed;
    }
    if (!publisher->empty()) {
      const auto parsed = PublisherId::parse(*publisher);
      if (!parsed.has_value()) return malformed("snapshot member provenance publisher is invalid");
      member.provenance.publisher = *parsed;
    }
    if (!boot->empty()) {
      const auto parsed = WorkerBootId::parse(*boot);
      if (!parsed.has_value()) return malformed("snapshot member provenance boot is invalid");
      member.provenance.worker_boot = *parsed;
    }
    if (*epoch != 0) {
      const auto parsed = CoordinatorEpoch::from_value(*epoch);
      if (!parsed.has_value()) return malformed("snapshot member provenance epoch is invalid");
      member.provenance.epoch = *parsed;
    }
    if (!attempt->empty()) {
      const auto parsed = MutationAttemptId::parse(*attempt);
      if (!parsed.has_value()) return malformed("snapshot member provenance attempt is invalid");
      member.provenance.attempt = *parsed;
    }
    snapshot.members.push_back(std::move(member));
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome encode_explanation(detail::ByteWriter& writer, const SetExplanation& explanation) {
  writer.string(explanation.set_id.view(), kMaxIdLength);
  write_key(writer, explanation.key);
  writer.u8(static_cast<std::uint8_t>(explanation.lifecycle));
  writer.u8(static_cast<std::uint8_t>(explanation.currentness));
  writer.u8(static_cast<std::uint8_t>(explanation.readiness));
  writer.u64(explanation.member_count);
  writer.u64(explanation.usable_member_count);
  writer.u64(explanation.minimum_usable_members);
  writer.boolean(explanation.minimum_satisfied);
  writer.boolean(explanation.admin_enabled);
  writer.boolean(explanation.conditional_authority_permitted);
  writer.u64(explanation.governing_epoch.value());
  writer.u64(explanation.authority_generation.value());
  writer.u8(static_cast<std::uint8_t>(explanation.last_cause));
  writer.boolean(explanation.last_mutating_publisher.has_value());
  if (explanation.last_mutating_publisher.has_value()) {
    writer.string(explanation.last_mutating_publisher->view(), kMaxIdLength);
  }
  const auto reason_count = detail::narrow_u32(explanation.reasons.size());
  if (!reason_count.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "explanation reason count is not "
                                                       "representable");
  }
  writer.u32(*reason_count);
  for (const auto reason : explanation.reasons) {
    writer.u8(static_cast<std::uint8_t>(reason));
  }
  const auto member_count = detail::narrow_u32(explanation.members.size());
  if (!member_count.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "explanation member count is not "
                                                       "representable");
  }
  writer.u32(*member_count);
  for (const auto& member : explanation.members) {
    writer.string(member.id.view(), kMaxIdLength);
    writer.string(member.path_id.view(), kMaxIdLength);
    writer.u8(static_cast<std::uint8_t>(member.lifecycle));
    writer.u8(static_cast<std::uint8_t>(member.currentness));
    writer.boolean(member.admin_enabled);
    writer.boolean(member.usable);
    writer.u64(member.bound_authority_generation.value());
    writer.boolean(member.observed_authority_generation.has_value());
    if (member.observed_authority_generation.has_value()) {
      writer.u64(member.observed_authority_generation->value());
    }
    writer.boolean(member.observed_authority_state.has_value());
    if (member.observed_authority_state.has_value()) {
      writer.u8(static_cast<std::uint8_t>(*member.observed_authority_state));
    }
    writer.u32(member.pending_revalidations);
    writer.u8(static_cast<std::uint8_t>(member.reason));
  }
  writer.boolean(explanation.truncated);
  if (writer.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "explanation encoding exceeded its bound");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_explanation(detail::ByteReader& reader, SetExplanation& explanation) {
  const auto set_id = reader.string(kMaxIdLength);
  if (!set_id.has_value()) {
    return malformed("explanation set identity is truncated");
  }
  const auto set_id_value = MultipathSetId::parse(*set_id);
  if (!set_id_value.has_value()) {
    return malformed("explanation carries an invalid set identity");
  }
  explanation = SetExplanation{};
  explanation.set_id = *set_id_value;
  if (!read_key(reader, explanation.key)) {
    return malformed("explanation key is truncated or malformed");
  }
  const auto lifecycle = reader.u8();
  const auto currentness = reader.u8();
  const auto readiness = reader.u8();
  const auto member_count = reader.u64();
  const auto usable = reader.u64();
  const auto minimum = reader.u64();
  const auto minimum_satisfied = reader.boolean();
  const auto admin_enabled = reader.boolean();
  const auto conditional = reader.boolean();
  const auto governing_epoch = reader.u64();
  const auto authority_generation = reader.u64();
  const auto last_cause = reader.u8();
  if (!lifecycle.has_value() || !currentness.has_value() || !readiness.has_value() ||
      !member_count.has_value() || !usable.has_value() || !minimum.has_value() ||
      !minimum_satisfied.has_value() || !admin_enabled.has_value() || !conditional.has_value() ||
      !governing_epoch.has_value() || !authority_generation.has_value() ||
      !last_cause.has_value()) {
    return malformed("explanation scalar block is truncated");
  }
  if (!valid_set_lifecycle(*lifecycle) || !valid_set_currentness(*currentness) ||
      !valid_route_readiness(*readiness) || !valid_membership_cause(*last_cause)) {
    return malformed("explanation carries a malformed enumerator");
  }
  const auto epoch_value = CoordinatorEpoch::from_value(*governing_epoch);
  const auto authority_value = MultipathAuthorityGeneration::from_value(*authority_generation);
  if (!epoch_value.has_value() || !authority_value.has_value()) {
    return malformed("explanation carries an impossible generation");
  }
  explanation.lifecycle = static_cast<SetLifecycle>(*lifecycle);
  explanation.currentness = static_cast<SetCurrentness>(*currentness);
  explanation.readiness = static_cast<RouteReadiness>(*readiness);
  explanation.member_count = *member_count;
  explanation.usable_member_count = *usable;
  explanation.minimum_usable_members = *minimum;
  explanation.minimum_satisfied = *minimum_satisfied;
  explanation.admin_enabled = *admin_enabled;
  explanation.conditional_authority_permitted = *conditional;
  explanation.governing_epoch = *epoch_value;
  explanation.authority_generation = *authority_value;
  explanation.last_cause = static_cast<MembershipCause>(*last_cause);
  const auto has_publisher = reader.boolean();
  if (!has_publisher.has_value()) {
    return malformed("explanation publisher flag is truncated");
  }
  if (*has_publisher) {
    const auto publisher = reader.string(kMaxIdLength);
    if (!publisher.has_value()) return malformed("explanation publisher is truncated");
    const auto parsed = PublisherId::parse(*publisher);
    if (!parsed.has_value()) return malformed("explanation publisher is invalid");
    explanation.last_mutating_publisher = *parsed;
  }
  const auto reason_count = reader.u32();
  if (!reason_count.has_value()) {
    return malformed("explanation reason count is truncated");
  }
  if (*reason_count > 4096U) {
    return malformed("explanation declares an absurd reason count");
  }
  for (std::uint32_t i = 0; i < *reason_count; ++i) {
    const auto reason = reader.u8();
    if (!reason.has_value()) return malformed("explanation reason is truncated");
    if (!valid_explanation_reason(*reason)) {
      return malformed("explanation carries a malformed reason");
    }
    explanation.reasons.push_back(static_cast<ExplanationReason>(*reason));
  }
  const auto count = reader.u32();
  if (!count.has_value()) return malformed("explanation member count is truncated");
  if (*count > 1000000U) return malformed("explanation declares an absurd member count");
  explanation.members.reserve(*count);
  for (std::uint32_t i = 0; i < *count; ++i) {
    MemberExplanation member;
    const auto id = reader.string(kMaxIdLength);
    const auto path = reader.string(kMaxIdLength);
    const auto member_lifecycle = reader.u8();
    const auto member_currentness = reader.u8();
    const auto member_admin = reader.boolean();
    const auto member_usable = reader.boolean();
    const auto bound = reader.u64();
    const auto has_observed_generation = reader.boolean();
    if (!id.has_value() || !path.has_value() || !member_lifecycle.has_value() ||
        !member_currentness.has_value() || !member_admin.has_value() ||
        !member_usable.has_value() || !bound.has_value() ||
        !has_observed_generation.has_value()) {
      return malformed("explanation member block is truncated");
    }
    std::optional<std::uint64_t> observed_generation;
    if (*has_observed_generation) {
      observed_generation = reader.u64();
      if (!observed_generation.has_value()) {
        return malformed("explanation observed generation is truncated");
      }
    }
    const auto has_observed_state = reader.boolean();
    if (!has_observed_state.has_value()) {
      return malformed("explanation observed state flag is truncated");
    }
    std::optional<std::uint8_t> observed_state;
    if (*has_observed_state) {
      observed_state = reader.u8();
      if (!observed_state.has_value()) {
        return malformed("explanation observed state is truncated");
      }
      if (!valid_path_authority_state(*observed_state)) {
        return malformed("explanation observed state is malformed");
      }
    }
    const auto pending = reader.u32();
    const auto reason = reader.u8();
    if (!pending.has_value() || !reason.has_value()) {
      return malformed("explanation member tail is truncated");
    }
    if (!valid_member_lifecycle(*member_lifecycle) ||
        !valid_member_currentness(*member_currentness) ||
        !valid_explanation_reason(*reason)) {
      return malformed("explanation member carries a malformed enumerator");
    }
    const auto id_value = MultipathMemberId::parse(*id);
    const auto path_value = PathId::parse(*path);
    const auto bound_value = PathAuthorityGeneration::from_value(*bound);
    if (!id_value.has_value() || !path_value.has_value() || !bound_value.has_value()) {
      return malformed("explanation member carries an invalid identity or generation");
    }
    if (observed_generation.has_value()) {
      const auto parsed = PathAuthorityGeneration::from_value(*observed_generation);
      if (!parsed.has_value()) {
        return malformed("explanation member observed generation is impossible");
      }
      member.observed_authority_generation = *parsed;
    }
    if (observed_state.has_value()) {
      member.observed_authority_state = static_cast<PathAuthorityState>(*observed_state);
    }
    member.id = *id_value;
    member.path_id = *path_value;
    member.lifecycle = static_cast<MemberLifecycle>(*member_lifecycle);
    member.currentness = static_cast<MemberCurrentness>(*member_currentness);
    member.admin_enabled = *member_admin;
    member.usable = *member_usable;
    member.bound_authority_generation = *bound_value;
    member.pending_revalidations = *pending;
    member.reason = static_cast<ExplanationReason>(*reason);
    explanation.members.push_back(std::move(member));
  }
  const auto truncated = reader.boolean();
  if (!truncated.has_value()) {
    return malformed("explanation truncated flag is missing");
  }
  explanation.truncated = *truncated;
  return make_outcome(OutcomeCode::OK, std::string());
}

// ---------------------------------------------------------------------------
// Request codec
// ---------------------------------------------------------------------------

FabricOutcome encode_request(const WireRequest& request, std::vector<std::uint8_t>& out) {
  detail::ByteWriter writer(1U << 20);
  switch (request.id) {
    case MessageId::HELLO:
    case MessageId::LIST_SETS:
    case MessageId::SHUTDOWN:
      break;
    case MessageId::REGISTER_PUBLISHER:
      writer.string(request.context.publisher.valid() ? request.context.publisher.view()
                                                      : std::string_view(""),
                    kMaxIdLength);
      writer.string(request.context.worker_boot.valid() ? request.context.worker_boot.view()
                                                        : std::string_view(""),
                    kMaxIdLength);
      writer.string(request.context.session.valid() ? request.context.session.view()
                                                    : std::string_view(""),
                    kMaxIdLength);
      write_scope(writer, request.scope);
      break;
    case MessageId::CREATE_SET:
      write_context(writer, request.context);
      write_key(writer, request.key);
      writer.u64(request.options.minimum_usable_members);
      writer.boolean(request.options.admin_enabled);
      writer.boolean(request.options.conditional_authority_permitted);
      break;
    case MessageId::ADD_MEMBER:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.path_id.view(), kMaxIdLength);
      writer.u64(request.path_authority_generation.value());
      break;
    case MessageId::ADD_MEMBERS: {
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      const auto count = detail::narrow_u32(request.members.size());
      if (!count.has_value()) {
        return make_rejection(OutcomeCode::RESOURCE_LIMIT, "batch size is not representable");
      }
      writer.u32(*count);
      for (const auto& member : request.members) {
        writer.string(member.path_id.view(), kMaxIdLength);
        writer.u64(member.authority_generation.value());
      }
      break;
    }
    case MessageId::REMOVE_MEMBER:
    case MessageId::WITHDRAW_MEMBER:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.member_id.view(), kMaxIdLength);
      writer.string(request.text, kMaxTextLength);
      break;
    case MessageId::REPLACE_MEMBER:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.member_id.view(), kMaxIdLength);
      writer.string(request.path_id.view(), kMaxIdLength);
      writer.u64(request.path_authority_generation.value());
      writer.string(request.text, kMaxTextLength);
      break;
    case MessageId::SET_MINIMUM:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.u64(request.number);
      break;
    case MessageId::SET_CONDITIONAL_POLICY:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.boolean(request.flag);
      break;
    case MessageId::SET_ADMIN_ENABLE:
    case MessageId::SET_ADMIN_DISABLE:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      break;
    case MessageId::MEMBER_ADMIN_ENABLE:
    case MessageId::MEMBER_ADMIN_DISABLE:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.member_id.view(), kMaxIdLength);
      break;
    case MessageId::REVALIDATE_MEMBER:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.member_id.view(), kMaxIdLength);
      break;
    case MessageId::REVALIDATE_SET:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      break;
    case MessageId::REVOKE_SET:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.u8(static_cast<std::uint8_t>(request.revocation_reason));
      writer.string(request.text, kMaxTextLength);
      break;
    case MessageId::RETIRE_SET:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.text, kMaxTextLength);
      break;
    case MessageId::SUPERSEDE_SET:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.path_id.view(), kMaxIdLength);
      break;
    case MessageId::EPOCH_ADVANCE:
      write_context(writer, request.context);
      writer.u64(request.number);
      break;
    case MessageId::ADVANCE_SET_STATE:
      write_context(writer, request.context);
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.u8(static_cast<std::uint8_t>(request.state_action));
      writer.string(request.text, kMaxTextLength);
      break;
    case MessageId::APPLY_PATH_AUTHORITY:
    case MessageId::DECLARE_PATH_AUTHORITY:
      write_context(writer, request.context);
      writer.string(request.path_id.view(), kMaxIdLength);
      writer.u64(request.path_authority_generation.value());
      writer.u8(static_cast<std::uint8_t>(request.path_state));
      break;
    case MessageId::REFRESH_PATH:
      write_context(writer, request.context);
      writer.string(request.path_id.view(), kMaxIdLength);
      break;
    case MessageId::QUERY_SET:
    case MessageId::EXPLAIN_SET:
      writer.string(request.set_id.view(), kMaxIdLength);
      break;
    case MessageId::SNAPSHOT_REQUEST:
      writer.string(request.set_id.view(), kMaxIdLength);
      writer.string(request.snapshot_id.view(), kMaxIdLength);
      break;
    case MessageId::HELLO_ACK:
    case MessageId::SNAPSHOT_RESPONSE:
    case MessageId::FENCE_NOTICE:
    case MessageId::RESULT:
    case MessageId::ERROR:
      return make_rejection(OutcomeCode::MALFORMED_REQUEST,
                            std::string(to_string(request.id)) +
                                " is not a client request message");
  }
  if (writer.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "request encoding exceeded its bound");
  }
  out = writer.take();
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_request(MessageId id, detail::ByteReader& reader, WireRequest& out) {
  out = WireRequest{};
  out.id = id;
  switch (id) {
    case MessageId::HELLO:
    case MessageId::LIST_SETS:
    case MessageId::SHUTDOWN:
      break;
    case MessageId::REGISTER_PUBLISHER: {
      const auto publisher = reader.string(kMaxIdLength);
      const auto boot = reader.string(kMaxIdLength);
      const auto session = reader.string(kMaxIdLength);
      if (!publisher.has_value() || !boot.has_value() || !session.has_value()) {
        return malformed("register request is truncated");
      }
      const auto publisher_id = PublisherId::parse(*publisher);
      const auto boot_id = WorkerBootId::parse(*boot);
      const auto session_id = SessionId::parse(*session);
      if (!publisher_id.has_value() || !boot_id.has_value() || !session_id.has_value()) {
        return malformed("register request carries an invalid identity");
      }
      out.context.publisher = *publisher_id;
      out.context.worker_boot = *boot_id;
      out.context.session = *session_id;
      if (!read_scope(reader, out.scope)) {
        return malformed("register request scope is truncated or malformed");
      }
      break;
    }
    case MessageId::CREATE_SET:
      if (!read_context(reader, out.context)) {
        return malformed("create request context is truncated or malformed");
      }
      if (!read_key(reader, out.key)) {
        return malformed("create request key is truncated or malformed");
      }
      {
        const auto minimum = reader.u64();
        const auto admin = reader.boolean();
        const auto conditional = reader.boolean();
        if (!minimum.has_value() || !admin.has_value() || !conditional.has_value()) {
          return malformed("create request options are truncated");
        }
        out.options.minimum_usable_members = *minimum;
        out.options.admin_enabled = *admin;
        out.options.conditional_authority_permitted = *conditional;
      }
      break;
    case MessageId::ADD_MEMBER: {
      if (!read_context(reader, out.context)) {
        return malformed("add request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto path = reader.string(kMaxIdLength);
      const auto generation = reader.u64();
      if (!set_id.has_value() || !path.has_value() || !generation.has_value()) {
        return malformed("add request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      const auto path_value = PathId::parse(*path);
      const auto generation_value = PathAuthorityGeneration::from_value(*generation);
      if (!set_id_value.has_value() || !path_value.has_value() ||
          !generation_value.has_value()) {
        return malformed("add request carries an invalid identity or generation");
      }
      out.set_id = *set_id_value;
      out.path_id = *path_value;
      out.path_authority_generation = *generation_value;
      break;
    }
    case MessageId::ADD_MEMBERS: {
      if (!read_context(reader, out.context)) {
        return malformed("bulk add request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto count = reader.u32();
      if (!set_id.has_value() || !count.has_value()) {
        return malformed("bulk add request is truncated");
      }
      if (*count > 100000U) {
        return malformed("bulk add request declares an absurd member count");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("bulk add request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.members.reserve(*count);
      for (std::uint32_t i = 0; i < *count; ++i) {
        const auto path = reader.string(kMaxIdLength);
        const auto generation = reader.u64();
        if (!path.has_value() || !generation.has_value()) {
          return malformed("bulk add member entry is truncated");
        }
        const auto path_value = PathId::parse(*path);
        const auto generation_value = PathAuthorityGeneration::from_value(*generation);
        if (!path_value.has_value() || !generation_value.has_value()) {
          return malformed("bulk add member entry carries an invalid identity or generation");
        }
        MemberRequest member;
        member.path_id = *path_value;
        member.authority_generation = *generation_value;
        out.members.push_back(std::move(member));
      }
      break;
    }
    case MessageId::REMOVE_MEMBER:
    case MessageId::WITHDRAW_MEMBER:
    case MessageId::REVALIDATE_MEMBER:
    case MessageId::MEMBER_ADMIN_ENABLE:
    case MessageId::MEMBER_ADMIN_DISABLE: {
      if (!read_context(reader, out.context)) {
        return malformed("member request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto member_id = reader.string(kMaxIdLength);
      if (!set_id.has_value() || !member_id.has_value()) {
        return malformed("member request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      const auto member_id_value = MultipathMemberId::parse(*member_id);
      if (!set_id_value.has_value() || !member_id_value.has_value()) {
        return malformed("member request carries an invalid identity");
      }
      out.set_id = *set_id_value;
      out.member_id = *member_id_value;
      if (id == MessageId::REMOVE_MEMBER || id == MessageId::WITHDRAW_MEMBER) {
        const auto reason = reader.string(kMaxTextLength);
        if (!reason.has_value()) {
          return malformed("member removal reason is truncated");
        }
        out.text = *reason;
      }
      break;
    }
    case MessageId::REPLACE_MEMBER: {
      if (!read_context(reader, out.context)) {
        return malformed("replace request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto member_id = reader.string(kMaxIdLength);
      const auto path = reader.string(kMaxIdLength);
      const auto generation = reader.u64();
      const auto reason = reader.string(kMaxTextLength);
      if (!set_id.has_value() || !member_id.has_value() || !path.has_value() ||
          !generation.has_value() || !reason.has_value()) {
        return malformed("replace request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      const auto member_id_value = MultipathMemberId::parse(*member_id);
      const auto path_value = PathId::parse(*path);
      const auto generation_value = PathAuthorityGeneration::from_value(*generation);
      if (!set_id_value.has_value() || !member_id_value.has_value() ||
          !path_value.has_value() || !generation_value.has_value()) {
        return malformed("replace request carries an invalid identity or generation");
      }
      out.set_id = *set_id_value;
      out.member_id = *member_id_value;
      out.path_id = *path_value;
      out.path_authority_generation = *generation_value;
      out.text = *reason;
      break;
    }
    case MessageId::SET_MINIMUM: {
      if (!read_context(reader, out.context)) {
        return malformed("minimum request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto minimum = reader.u64();
      if (!set_id.has_value() || !minimum.has_value()) {
        return malformed("minimum request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("minimum request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.number = *minimum;
      break;
    }
    case MessageId::SET_CONDITIONAL_POLICY: {
      if (!read_context(reader, out.context)) {
        return malformed("policy request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto permitted = reader.boolean();
      if (!set_id.has_value() || !permitted.has_value()) {
        return malformed("policy request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("policy request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.flag = *permitted;
      break;
    }
    case MessageId::SET_ADMIN_ENABLE:
    case MessageId::SET_ADMIN_DISABLE:
    case MessageId::REVALIDATE_SET: {
      if (!read_context(reader, out.context)) {
        return malformed("set request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      if (!set_id.has_value()) {
        return malformed("set request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("set request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      break;
    }
    case MessageId::REVOKE_SET: {
      if (!read_context(reader, out.context)) {
        return malformed("revoke request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto reason = reader.u8();
      const auto detail = reader.string(kMaxTextLength);
      if (!set_id.has_value() || !reason.has_value() || !detail.has_value()) {
        return malformed("revoke request is truncated");
      }
      if (!valid_revocation_reason(*reason)) {
        return malformed("revoke request carries a malformed reason code");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("revoke request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.revocation_reason = static_cast<RevocationReason>(*reason);
      out.text = *detail;
      break;
    }
    case MessageId::RETIRE_SET: {
      if (!read_context(reader, out.context)) {
        return malformed("retire request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto reason = reader.string(kMaxTextLength);
      if (!set_id.has_value() || !reason.has_value()) {
        return malformed("retire request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("retire request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.text = *reason;
      break;
    }
    case MessageId::SUPERSEDE_SET: {
      if (!read_context(reader, out.context)) {
        return malformed("supersede request context is truncated or malformed");
      }
      const auto predecessor = reader.string(kMaxIdLength);
      const auto successor = reader.string(kMaxIdLength);
      if (!predecessor.has_value() || !successor.has_value()) {
        return malformed("supersede request is truncated");
      }
      const auto predecessor_value = MultipathSetId::parse(*predecessor);
      const auto successor_value = MultipathSetId::parse(*successor);
      if (!predecessor_value.has_value() || !successor_value.has_value()) {
        return malformed("supersede request carries an invalid set identity");
      }
      out.set_id = *predecessor_value;
      out.text = successor_value->str();
      break;
    }
    case MessageId::EPOCH_ADVANCE: {
      if (!read_context(reader, out.context)) {
        return malformed("epoch advance context is truncated or malformed");
      }
      const auto expected = reader.u64();
      if (!expected.has_value()) {
        return malformed("epoch advance request is truncated");
      }
      if (!CoordinatorEpoch::from_value(*expected).has_value()) {
        return malformed("epoch advance request carries an impossible epoch");
      }
      out.number = *expected;
      break;
    }
    case MessageId::ADVANCE_SET_STATE: {
      if (!read_context(reader, out.context)) {
        return malformed("set state request context is truncated or malformed");
      }
      const auto set_id = reader.string(kMaxIdLength);
      const auto action = reader.u8();
      const auto reason = reader.string(kMaxTextLength);
      if (!set_id.has_value() || !action.has_value() || !reason.has_value()) {
        return malformed("set state request is truncated");
      }
      if (!valid_set_state_action(*action)) {
        return malformed("set state request carries a malformed action selector");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("set state request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      out.state_action = static_cast<SetStateAction>(*action);
      out.text = *reason;
      break;
    }
    case MessageId::APPLY_PATH_AUTHORITY:
    case MessageId::DECLARE_PATH_AUTHORITY: {
      if (!read_context(reader, out.context)) {
        return malformed("path authority request context is truncated or malformed");
      }
      const auto path = reader.string(kMaxIdLength);
      const auto generation = reader.u64();
      const auto state = reader.u8();
      if (!path.has_value() || !generation.has_value() || !state.has_value()) {
        return malformed("path authority request is truncated");
      }
      if (!valid_path_authority_state(*state)) {
        return malformed("path authority request carries a malformed state");
      }
      const auto path_value = PathId::parse(*path);
      const auto generation_value = PathAuthorityGeneration::from_value(*generation);
      if (!path_value.has_value() || !generation_value.has_value()) {
        return malformed("path authority request carries an invalid identity or generation");
      }
      out.path_id = *path_value;
      out.path_authority_generation = *generation_value;
      out.path_state = static_cast<PathAuthorityState>(*state);
      break;
    }
    case MessageId::REFRESH_PATH: {
      if (!read_context(reader, out.context)) {
        return malformed("refresh request context is truncated or malformed");
      }
      const auto path = reader.string(kMaxIdLength);
      if (!path.has_value()) {
        return malformed("refresh request is truncated");
      }
      const auto path_value = PathId::parse(*path);
      if (!path_value.has_value()) {
        return malformed("refresh request carries an invalid path identity");
      }
      out.path_id = *path_value;
      break;
    }
    case MessageId::QUERY_SET:
    case MessageId::EXPLAIN_SET: {
      const auto set_id = reader.string(kMaxIdLength);
      if (!set_id.has_value()) {
        return malformed("query request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      if (!set_id_value.has_value()) {
        return malformed("query request carries an invalid set identity");
      }
      out.set_id = *set_id_value;
      break;
    }
    case MessageId::SNAPSHOT_REQUEST: {
      const auto set_id = reader.string(kMaxIdLength);
      const auto snapshot_id = reader.string(kMaxIdLength);
      if (!set_id.has_value() || !snapshot_id.has_value()) {
        return malformed("snapshot request is truncated");
      }
      const auto set_id_value = MultipathSetId::parse(*set_id);
      const auto snapshot_id_value = SnapshotId::parse(*snapshot_id);
      if (!set_id_value.has_value() || !snapshot_id_value.has_value()) {
        return malformed("snapshot request carries an invalid identity");
      }
      out.set_id = *set_id_value;
      out.snapshot_id = *snapshot_id_value;
      break;
    }
    case MessageId::HELLO_ACK:
    case MessageId::SNAPSHOT_RESPONSE:
    case MessageId::FENCE_NOTICE:
    case MessageId::RESULT:
    case MessageId::ERROR:
      return make_rejection(OutcomeCode::PROTOCOL_ERROR,
                            std::string(to_string(id)) + " is not a client request message");
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

// ---------------------------------------------------------------------------
// Response codec
// ---------------------------------------------------------------------------

FabricOutcome encode_response(const WireResponse& response, std::vector<std::uint8_t>& out) {
  detail::ByteWriter writer(1U << 20);
  FabricOutcome encoded = encode_outcome(writer, response.outcome);
  if (!encoded.succeeded()) {
    return encoded;
  }
  writer.boolean(response.snapshot.has_value());
  if (response.snapshot.has_value()) {
    encoded = encode_snapshot(writer, *response.snapshot);
    if (!encoded.succeeded()) {
      return encoded;
    }
  }
  writer.boolean(response.explanation.has_value());
  if (response.explanation.has_value()) {
    encoded = encode_explanation(writer, *response.explanation);
    if (!encoded.succeeded()) {
      return encoded;
    }
  }
  const auto count = detail::narrow_u32(response.set_ids.size());
  if (!count.has_value()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "set id list is not representable");
  }
  writer.u32(*count);
  for (const auto& id : response.set_ids) {
    writer.string(id.view(), kMaxIdLength);
  }
  if (writer.overflowed()) {
    return make_rejection(OutcomeCode::RESOURCE_LIMIT, "response encoding exceeded its bound");
  }
  out = writer.take();
  return make_outcome(OutcomeCode::OK, std::string());
}

FabricOutcome decode_response(detail::ByteReader& reader, WireResponse& response) {
  response = WireResponse{};
  FabricOutcome result = decode_outcome(reader, response.outcome);
  if (!result.succeeded()) {
    return result;
  }
  const auto has_snapshot = reader.boolean();
  if (!has_snapshot.has_value()) {
    return malformed("response snapshot flag is truncated");
  }
  if (*has_snapshot) {
    SetSnapshot snapshot;
    result = decode_snapshot(reader, snapshot);
    if (!result.succeeded()) {
      return result;
    }
    response.snapshot = std::move(snapshot);
  }
  const auto has_explanation = reader.boolean();
  if (!has_explanation.has_value()) {
    return malformed("response explanation flag is truncated");
  }
  if (*has_explanation) {
    SetExplanation explanation;
    result = decode_explanation(reader, explanation);
    if (!result.succeeded()) {
      return result;
    }
    response.explanation = std::move(explanation);
  }
  const auto count = reader.u32();
  if (!count.has_value()) {
    return malformed("response set id count is truncated");
  }
  if (*count > 1000000U) {
    return malformed("response declares an absurd set id count");
  }
  response.set_ids.reserve(*count);
  for (std::uint32_t i = 0; i < *count; ++i) {
    const auto value = reader.string(kMaxIdLength);
    if (!value.has_value()) {
      return malformed("response set id is truncated");
    }
    const auto parsed = MultipathSetId::parse(*value);
    if (!parsed.has_value()) {
      return malformed("response carries an invalid set identity");
    }
    response.set_ids.push_back(*parsed);
  }
  return make_outcome(OutcomeCode::OK, std::string());
}

}  // namespace multipath_fabric::wire
