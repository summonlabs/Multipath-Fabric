#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"
#include "test_support.hpp"

using namespace multipath_fabric;

namespace {

[[nodiscard]] std::vector<std::uint8_t> frame_for(wire::MessageId id,
                                                  const std::vector<std::uint8_t>& payload,
                                                  std::uint64_t bound = 1U << 20) {
  std::vector<std::uint8_t> frame;
  const FabricOutcome outcome = wire::encode_frame(id, payload, bound, frame);
  MPF_CHECK(outcome.succeeded());
  return frame;
}

[[nodiscard]] std::uint64_t integrity_of(const std::vector<std::uint8_t>& frame,
                                         std::size_t payload_length) {
  detail::DigestBuilder builder;
  builder.absorb_bytes(std::string_view(reinterpret_cast<const char*>(frame.data()),
                                        wire::frame_integrity_offset));
  builder.absorb_bytes(std::string_view(
      reinterpret_cast<const char*>(frame.data() + wire::frame_header_size), payload_length));
  return builder.finish().high;
}

}  // namespace

MPF_TEST(wire_message_ids_are_frozen) {
  // Stable explicit numeric ids: the wire contract must never drift because an
  // enumerator was inserted.
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::HELLO), std::uint16_t{1});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::HELLO_ACK), std::uint16_t{2});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REGISTER_PUBLISHER), std::uint16_t{3});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::CREATE_SET), std::uint16_t{4});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::ADD_MEMBER), std::uint16_t{5});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REMOVE_MEMBER), std::uint16_t{6});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REVALIDATE_MEMBER), std::uint16_t{7});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REVALIDATE_SET), std::uint16_t{8});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REVOKE_SET), std::uint16_t{9});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::RETIRE_SET), std::uint16_t{10});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::QUERY_SET), std::uint16_t{11});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SNAPSHOT_REQUEST), std::uint16_t{12});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SNAPSHOT_RESPONSE), std::uint16_t{13});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::FENCE_NOTICE), std::uint16_t{14});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::RESULT), std::uint16_t{15});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::ERROR), std::uint16_t{16});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REPLACE_MEMBER), std::uint16_t{17});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SET_MINIMUM), std::uint16_t{18});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SET_ADMIN_ENABLE), std::uint16_t{19});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SET_ADMIN_DISABLE), std::uint16_t{20});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::MEMBER_ADMIN_ENABLE),
               std::uint16_t{21});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::MEMBER_ADMIN_DISABLE),
               std::uint16_t{22});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::EPOCH_ADVANCE), std::uint16_t{23});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::LIST_SETS), std::uint16_t{24});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::ADVANCE_SET_STATE), std::uint16_t{25});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::APPLY_PATH_AUTHORITY),
               std::uint16_t{26});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::REFRESH_PATH), std::uint16_t{27});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::ADD_MEMBERS), std::uint16_t{28});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::WITHDRAW_MEMBER), std::uint16_t{29});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SET_CONDITIONAL_POLICY),
               std::uint16_t{30});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SUPERSEDE_SET), std::uint16_t{31});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::SHUTDOWN), std::uint16_t{32});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::EXPLAIN_SET), std::uint16_t{33});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(wire::MessageId::DECLARE_PATH_AUTHORITY),
               std::uint16_t{34});
  for (std::uint16_t raw = wire::message_id_min; raw <= wire::message_id_max; ++raw) {
    MPF_CHECK(wire::valid_message_id(raw));
    const auto parsed = wire::parse_message_id(wire::to_string(static_cast<wire::MessageId>(raw)));
    MPF_CHECK(parsed.has_value());
  }
  MPF_CHECK(!wire::valid_message_id(0));
  MPF_CHECK(!wire::valid_message_id(35));
  MPF_CHECK(!wire::valid_message_id(65535));
}

MPF_TEST(outcome_codes_are_frozen) {
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::OK), std::uint16_t{0});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::CREATED), std::uint16_t{1});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::IDEMPOTENT), std::uint16_t{3});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::MEMBER_REVALIDATION_NEGATIVE),
               std::uint16_t{26});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::SET_REVALIDATION_INCOMPLETE),
               std::uint16_t{27});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::MALFORMED_REQUEST), std::uint16_t{100});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::STALE_EPOCH), std::uint16_t{103});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::STALE_REVALIDATION), std::uint16_t{123});
  MPF_CHECK_EQ(static_cast<std::uint16_t>(OutcomeCode::INTERNAL_ERROR), std::uint16_t{143});
  for (std::uint16_t raw = 0; raw <= 200; ++raw) {
    if (!valid_outcome_code(raw)) {
      continue;
    }
    const auto code = static_cast<OutcomeCode>(raw);
    const auto parsed = parse_outcome_code(to_string(code));
    MPF_REQUIRE(parsed.has_value());
    MPF_CHECK(*parsed == code);
  }
  MPF_CHECK(outcome_is_success(OutcomeCode::OK));
  MPF_CHECK(outcome_is_success(OutcomeCode::MEMBER_REVALIDATION_NEGATIVE));
  MPF_CHECK(!outcome_is_success(OutcomeCode::STALE_EPOCH));
  MPF_CHECK(!valid_outcome_code(28));
  MPF_CHECK(!valid_outcome_code(99));
}

MPF_TEST(frame_round_trip_and_integrity_span) {
  const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  const std::vector<std::uint8_t> frame = frame_for(wire::MessageId::CREATE_SET, payload);
  MPF_CHECK_EQ(frame.size(), wire::frame_header_size + payload.size());
  // The magic and version are explicit and stable.
  MPF_CHECK_EQ(frame[0], std::uint8_t{'M'});
  MPF_CHECK_EQ(frame[1], std::uint8_t{'P'});
  MPF_CHECK_EQ(frame[2], std::uint8_t{'F'});
  MPF_CHECK_EQ(frame[3], std::uint8_t{'W'});
  MPF_CHECK_EQ(frame[4], static_cast<std::uint8_t>(wire_protocol_version & 0xFFU));
  MPF_CHECK_EQ(frame[6], std::uint8_t{4});  // CREATE_SET
  MPF_CHECK_EQ(frame[8], static_cast<std::uint8_t>(payload.size()));

  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t length = 0;
  MPF_REQUIRE(wire::decode_header(frame.data(), frame.size(), 1U << 20, id, length).succeeded());
  MPF_CHECK_EQ(id, wire::MessageId::CREATE_SET);
  MPF_CHECK_EQ(length, static_cast<std::uint32_t>(payload.size()));
  MPF_REQUIRE(wire::verify_integrity(frame.data(), frame.size(), payload).succeeded());

  // The integrity value covers the semantic header and the payload: corrupting
  // the message id, the payload length or any payload byte is detected.
  for (const std::size_t offset : {std::size_t{6}, std::size_t{8}, std::size_t{12}}) {
    std::vector<std::uint8_t> tampered = frame;
    tampered[offset] ^= 0x01U;
    std::vector<std::uint8_t> tampered_payload(payload.begin(), payload.end());
    MPF_CHECK(!wire::verify_integrity(tampered.data(), tampered.size(), tampered_payload).succeeded());
  }
  std::vector<std::uint8_t> tampered_payload = payload;
  tampered_payload[4] ^= 0x80U;
  MPF_CHECK(!wire::verify_integrity(frame.data(), frame.size(), tampered_payload).succeeded());
  std::uint64_t stored_integrity = 0;
  std::memcpy(&stored_integrity, frame.data() + wire::frame_integrity_offset,
              sizeof(stored_integrity));
  MPF_CHECK_EQ(integrity_of(frame, payload.size()), stored_integrity);
}

MPF_TEST(frame_rejects_structural_damage) {
  const std::vector<std::uint8_t> payload = {9, 9, 9};
  const std::vector<std::uint8_t> frame = frame_for(wire::MessageId::LIST_SETS, payload);

  const auto decode = [&](const std::vector<std::uint8_t>& candidate) {
    wire::MessageId id = wire::MessageId::HELLO;
    std::uint32_t length = 0;
    return wire::decode_header(candidate.data(), candidate.size(), 1U << 20, id, length);
  };

  std::vector<std::uint8_t> bad_magic = frame;
  bad_magic[0] = 'Z';
  MPF_CHECK_EQ(decode(bad_magic).code, OutcomeCode::FRAMING_ERROR);

  std::vector<std::uint8_t> bad_version = frame;
  bad_version[4] = 9;
  MPF_CHECK_EQ(decode(bad_version).code, OutcomeCode::UNSUPPORTED_WIRE_VERSION);

  std::vector<std::uint8_t> bad_message = frame;
  bad_message[6] = 200;
  MPF_CHECK_EQ(decode(bad_message).code, OutcomeCode::FRAMING_ERROR);

  std::vector<std::uint8_t> bad_flags = frame;
  bad_flags[12] = 1;
  MPF_CHECK_EQ(decode(bad_flags).code, OutcomeCode::FRAMING_ERROR);

  std::vector<std::uint8_t> bad_length = frame;
  bad_length[8] = 0xFFU;
  bad_length[9] = 0xFFU;
  bad_length[10] = 0xFFU;
  bad_length[11] = 0x7FU;
  MPF_CHECK(!decode(bad_length).succeeded());

  // A truncated header is refused rather than read out of bounds.
  std::vector<std::uint8_t> truncated(frame.begin(), frame.begin() + 12);
  wire::MessageId id = wire::MessageId::HELLO;
  std::uint32_t length = 0;
  MPF_CHECK(!wire::decode_header(truncated.data(), truncated.size(), 1U << 20, id, length).succeeded());
}

MPF_TEST(wire_request_codec_round_trips_set_and_member_messages) {
  mpf_test::FabricFixture fixture;
  MutationContext context = fixture.context();

  const auto round_trip = [&](const wire::WireRequest& request, wire::MessageId id) {
    std::vector<std::uint8_t> payload;
    const FabricOutcome encoded = wire::encode_request(request, payload);
    MPF_CHECK_MSG(encoded.succeeded(), std::string(wire::to_string(id)) + " encode");
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    const FabricOutcome result = wire::decode_request(id, reader, decoded);
    MPF_CHECK_MSG(result.succeeded(), std::string(wire::to_string(id)) + " decode: " +
                                          result.detail);
    MPF_CHECK_MSG(reader.at_end(), std::string(wire::to_string(id)) + " trailing bytes");
    return decoded;
  };

  {
      wire::WireRequest request;
      request.id = wire::MessageId::CREATE_SET;
      request.context = context;
      request.key.fabric = FabricId::require("fabric-a");
      request.key.name_space = MultipathNamespace::require("ns-a");
      request.key.name = MultipathSetName::require("name-a");
      request.options.minimum_usable_members = 3;
      request.options.admin_enabled = false;
      request.options.conditional_authority_permitted = true;
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::CREATE_SET);
      MPF_CHECK(decoded.context.epoch == context.epoch);
      MPF_CHECK(decoded.context.publisher == context.publisher);
      MPF_CHECK(decoded.context.attempt == context.attempt);
      MPF_CHECK_EQ(decoded.key.render(), request.key.render());
      MPF_CHECK_EQ(decoded.options.minimum_usable_members, std::uint64_t{3});
      MPF_CHECK(!decoded.options.admin_enabled);
      MPF_CHECK(decoded.options.conditional_authority_permitted);
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::ADD_MEMBER;
      request.context = context;
      request.set_id = MultipathSetId::require("set-1");
      request.path_id = PathId::require("path-1");
      request.path_authority_generation = PathAuthorityGeneration::require(7);
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::ADD_MEMBER);
      MPF_CHECK_EQ(decoded.set_id.view(), request.set_id.view());
      MPF_CHECK_EQ(decoded.path_id.view(), request.path_id.view());
      MPF_CHECK_EQ(decoded.path_authority_generation.value(), std::uint64_t{7});
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::ADD_MEMBERS;
      request.context = context;
      request.set_id = MultipathSetId::require("set-2");
      for (int index = 0; index < 3; ++index) {
        MemberRequest member;
        member.path_id = PathId::require("bulk-path-" + std::to_string(index));
        member.authority_generation = PathAuthorityGeneration::require(1);
        request.members.push_back(std::move(member));
      }
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::ADD_MEMBERS);
      MPF_CHECK_EQ(decoded.members.size(), std::size_t{3});
    }

}

MPF_TEST(wire_request_codec_round_trips_bulk_and_registration_messages) {
  mpf_test::FabricFixture fixture;
  MutationContext context = fixture.context();

  const auto round_trip = [&](const wire::WireRequest& request, wire::MessageId id) {
    std::vector<std::uint8_t> payload;
    const FabricOutcome encoded = wire::encode_request(request, payload);
    MPF_CHECK_MSG(encoded.succeeded(), std::string(wire::to_string(id)) + " encode");
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    const FabricOutcome result = wire::decode_request(id, reader, decoded);
    MPF_CHECK_MSG(result.succeeded(), std::string(wire::to_string(id)) + " decode: " +
                                          result.detail);
    MPF_CHECK_MSG(reader.at_end(), std::string(wire::to_string(id)) + " trailing bytes");
    return decoded;
  };

  {
      wire::WireRequest request;
      request.id = wire::MessageId::REGISTER_PUBLISHER;
      request.context.publisher = PublisherId::require("wire-publisher");
      request.context.worker_boot = WorkerBootId::require("wire-boot");
      request.context.session = SessionId::require("wire-session");
      request.scope.fabric = FabricId::require("fabric-a");
      request.scope.name_space = MultipathNamespace::require("ns-a");
      request.scope.set_ids.push_back(MultipathSetId::require("scope-set"));
      const wire::WireRequest decoded =
          round_trip(request, wire::MessageId::REGISTER_PUBLISHER);
      MPF_CHECK_EQ(decoded.scope.render(), request.scope.render());
    }

}

MPF_TEST(wire_request_codec_round_trips_lifecycle_and_path_messages) {
  mpf_test::FabricFixture fixture;
  MutationContext context = fixture.context();

  const auto round_trip = [&](const wire::WireRequest& request, wire::MessageId id) {
    std::vector<std::uint8_t> payload;
    const FabricOutcome encoded = wire::encode_request(request, payload);
    MPF_CHECK_MSG(encoded.succeeded(), std::string(wire::to_string(id)) + " encode");
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    const FabricOutcome result = wire::decode_request(id, reader, decoded);
    MPF_CHECK_MSG(result.succeeded(), std::string(wire::to_string(id)) + " decode: " +
                                          result.detail);
    MPF_CHECK_MSG(reader.at_end(), std::string(wire::to_string(id)) + " trailing bytes");
    return decoded;
  };

  {
      wire::WireRequest request;
      request.id = wire::MessageId::REVOKE_SET;
      request.context = context;
      request.set_id = MultipathSetId::require("set-3");
      request.revocation_reason = RevocationReason::SECURITY;
      request.text = "detail";
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::REVOKE_SET);
      MPF_CHECK_EQ(decoded.revocation_reason, RevocationReason::SECURITY);
      MPF_CHECK_EQ(decoded.text, std::string("detail"));
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::ADVANCE_SET_STATE;
      request.context = context;
      request.set_id = MultipathSetId::require("set-4");
      request.state_action = wire::SetStateAction::COMPLETE_WITHDRAWAL;
      request.text = "reason";
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::ADVANCE_SET_STATE);
      MPF_CHECK_EQ(decoded.state_action, wire::SetStateAction::COMPLETE_WITHDRAWAL);
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::DECLARE_PATH_AUTHORITY;
      request.context = context;
      request.path_id = PathId::require("declared-path");
      request.path_authority_generation = PathAuthorityGeneration::require(4);
      request.path_state = PathAuthorityState::CONDITIONALLY_AUTHORIZED;
      const wire::WireRequest decoded =
          round_trip(request, wire::MessageId::DECLARE_PATH_AUTHORITY);
      MPF_CHECK_EQ(decoded.path_state, PathAuthorityState::CONDITIONALLY_AUTHORIZED);
      MPF_CHECK_EQ(decoded.path_authority_generation.value(), std::uint64_t{4});
    }

}

MPF_TEST(wire_request_codec_round_trips_query_messages) {
  mpf_test::FabricFixture fixture;
  MutationContext context = fixture.context();

  const auto round_trip = [&](const wire::WireRequest& request, wire::MessageId id) {
    std::vector<std::uint8_t> payload;
    const FabricOutcome encoded = wire::encode_request(request, payload);
    MPF_CHECK_MSG(encoded.succeeded(), std::string(wire::to_string(id)) + " encode");
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    const FabricOutcome result = wire::decode_request(id, reader, decoded);
    MPF_CHECK_MSG(result.succeeded(), std::string(wire::to_string(id)) + " decode: " +
                                          result.detail);
    MPF_CHECK_MSG(reader.at_end(), std::string(wire::to_string(id)) + " trailing bytes");
    return decoded;
  };

  {
      wire::WireRequest request;
      request.id = wire::MessageId::QUERY_SET;
      request.set_id = MultipathSetId::require("set-5");
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::QUERY_SET);
      MPF_CHECK_EQ(decoded.set_id.view(), request.set_id.view());
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::REPLACE_MEMBER;
      request.context = context;
      request.set_id = MultipathSetId::require("set-6");
      request.member_id = MultipathMemberId::require("member-6");
      request.path_id = PathId::require("successor-path");
      request.path_authority_generation = PathAuthorityGeneration::require(2);
      request.text = "migrated";
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::REPLACE_MEMBER);
      MPF_CHECK_EQ(decoded.member_id.view(), request.member_id.view());
      MPF_CHECK_EQ(decoded.text, std::string("migrated"));
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::SET_MINIMUM;
      request.context = context;
      request.set_id = MultipathSetId::require("set-7");
      request.number = 5;
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::SET_MINIMUM);
      MPF_CHECK_EQ(decoded.number, std::uint64_t{5});
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::EPOCH_ADVANCE;
      request.context = context;
      request.number = 3;
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::EPOCH_ADVANCE);
      MPF_CHECK_EQ(decoded.number, std::uint64_t{3});
    }

  {
      wire::WireRequest request;
      request.id = wire::MessageId::SNAPSHOT_REQUEST;
      request.set_id = MultipathSetId::require("set-8");
      request.snapshot_id = SnapshotId::require("snap-0123456789abcdef0123456789abcdef");
      const wire::WireRequest decoded = round_trip(request, wire::MessageId::SNAPSHOT_REQUEST);
      MPF_CHECK_EQ(decoded.snapshot_id.view(), request.snapshot_id.view());
    }

}

MPF_TEST(request_decoder_rejects_malformed_and_trailing_bytes) {
  // A payload that is one byte short is refused.
  {
    wire::WireRequest request;
    request.id = wire::MessageId::SET_MINIMUM;
    request.context.epoch = CoordinatorEpoch::require(1);
    request.context.publisher = PublisherId::require("p");
    request.context.worker_boot = WorkerBootId::require("b");
    request.context.session = SessionId::require("s");
    request.context.attempt = MutationAttemptId::require("a");
    request.set_id = MultipathSetId::require("set");
    request.number = 1;
    std::vector<std::uint8_t> payload;
    MPF_REQUIRE(wire::encode_request(request, payload).succeeded());
    payload.pop_back();
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    MPF_CHECK(!wire::decode_request(wire::MessageId::SET_MINIMUM, reader, decoded).succeeded());
  }
  // Trailing bytes are detected by the caller's at_end check.
  {
    wire::WireRequest request;
    request.id = wire::MessageId::LIST_SETS;
    std::vector<std::uint8_t> payload;
    MPF_REQUIRE(wire::encode_request(request, payload).succeeded());
    payload.push_back(0x00);
    detail::ByteReader reader(payload.data(), payload.size());
    wire::WireRequest decoded;
    MPF_REQUIRE(wire::decode_request(wire::MessageId::LIST_SETS, reader, decoded).succeeded());
    MPF_CHECK(!reader.at_end());
    MPF_CHECK_EQ(reader.remaining(), std::size_t{1});
  }
  // A malformed enumerator inside a request is refused.
  {
    detail::ByteWriter writer(256);
    writer.u64(1);
    writer.string("publisher-x", 128);
    writer.string("boot-x", 128);
    writer.string("session-x", 128);
    writer.string("attempt-x", 128);
    writer.boolean(false);
    writer.boolean(false);
    writer.string("set-x", 128);
    writer.u8(200);  // malformed action selector
    writer.string("reason", 512);
    detail::ByteReader reader(writer.buffer().data(), writer.buffer().size());
    wire::WireRequest decoded;
    const FabricOutcome outcome =
        wire::decode_request(wire::MessageId::ADVANCE_SET_STATE, reader, decoded);
    MPF_CHECK(!outcome.succeeded());
    MPF_CHECK_EQ(outcome.code, OutcomeCode::MALFORMED_REQUEST);
  }
  // A server-only message is never accepted as a request.
  {
    detail::ByteReader reader(nullptr, 0);
    wire::WireRequest decoded;
    MPF_CHECK(!wire::decode_request(wire::MessageId::RESULT, reader, decoded).succeeded());
    MPF_CHECK(!wire::decode_request(wire::MessageId::ERROR, reader, decoded).succeeded());
    MPF_CHECK(!wire::decode_request(wire::MessageId::FENCE_NOTICE, reader, decoded).succeeded());
  }
}

MPF_TEST(response_codec_round_trips_outcome_snapshot_and_explanation) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("wire-response", 2, 3);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  const auto explanation = fixture.engine().explain_set(set_id);
  MPF_REQUIRE(snapshot.has_value());
  MPF_REQUIRE(explanation.has_value());

  wire::WireResponse response;
  response.outcome = make_outcome(OutcomeCode::MEMBER_ADDED, "detail text");
  response.outcome.set_id = set_id;
  response.outcome.path_id = PathId::require("wire-response-0");
  response.outcome.set_generation = snapshot->generation;
  response.outcome.membership_generation = snapshot->membership_generation;
  response.outcome.member_generation = snapshot->members[0].generation;
  response.outcome.authority_generation = snapshot->authority_generation;
  response.outcome.lifecycle = snapshot->lifecycle;
  response.outcome.currentness = snapshot->currentness;
  response.outcome.usable_members = snapshot->usable_member_count;
  response.outcome.minimum_usable_members = snapshot->minimum_usable_members;
  response.outcome.digest = snapshot->digest;
  response.snapshot = snapshot;
  response.explanation = explanation;
  response.set_ids = {set_id};

  std::vector<std::uint8_t> payload;
  const FabricOutcome encoded = wire::encode_response(response, payload);
  MPF_REQUIRE(encoded.succeeded());
  detail::ByteReader reader(payload.data(), payload.size());
  wire::WireResponse decoded;
  const FabricOutcome result = wire::decode_response(reader, decoded);
  MPF_CHECK_MSG(result.succeeded(), result.detail);
  MPF_REQUIRE(reader.at_end());

  MPF_CHECK_EQ(decoded.outcome.code, OutcomeCode::MEMBER_ADDED);
  MPF_CHECK_EQ(decoded.outcome.detail, std::string("detail text"));
  MPF_CHECK_EQ(decoded.outcome.set_generation->value(), snapshot->generation.value());
  MPF_CHECK_EQ(decoded.outcome.digest->to_hex(), snapshot->digest.to_hex());
  MPF_REQUIRE(decoded.snapshot.has_value());
  MPF_CHECK_EQ(decoded.snapshot->digest.to_hex(), snapshot->digest.to_hex());
  MPF_CHECK_EQ(decoded.snapshot->render(), snapshot->render());
  MPF_REQUIRE(decoded.explanation.has_value());
  MPF_CHECK_EQ(decoded.explanation->render(), explanation->render());
  MPF_CHECK_EQ(decoded.set_ids.size(), std::size_t{1});

  // A malformed outcome code in the payload is refused.
  std::vector<std::uint8_t> malformed = payload;
  malformed[0] = 0xFFU;
  malformed[1] = 0xFFU;
  detail::ByteReader bad_reader(malformed.data(), malformed.size());
  wire::WireResponse bad;
  MPF_CHECK(!wire::decode_response(bad_reader, bad).succeeded());
}

MPF_TEST(response_rejects_malformed_enumeration_in_a_snapshot) {
  mpf_test::FabricFixture fixture;
  const MultipathSetId set_id = fixture.build_set("wire-enum", 1, 1);
  MPF_REQUIRE(set_id.valid());
  const auto snapshot = fixture.engine().snapshot(set_id);
  MPF_REQUIRE(snapshot.has_value());
  wire::WireResponse response;
  response.outcome = make_outcome(OutcomeCode::OK, "ok");
  response.snapshot = snapshot;
  std::vector<std::uint8_t> payload;
  MPF_REQUIRE(wire::encode_response(response, payload).succeeded());

  // Flip the lifecycle enumerator of the snapshot to an out-of-domain value.
  // The outcome block is variable length, so locate the enumerator by rebuilding
  // the payload with a deliberately corrupted lifecycle instead.
  wire::WireResponse bad_response = response;
  bad_response.snapshot->lifecycle = static_cast<SetLifecycle>(200);
  std::vector<std::uint8_t> bad_payload;
  MPF_REQUIRE(wire::encode_response(bad_response, bad_payload).succeeded());
  detail::ByteReader reader(bad_payload.data(), bad_payload.size());
  wire::WireResponse decoded;
  const FabricOutcome outcome = wire::decode_response(reader, decoded);
  MPF_CHECK(!outcome.succeeded());
  MPF_CHECK_EQ(outcome.code, OutcomeCode::MALFORMED_REQUEST);
}