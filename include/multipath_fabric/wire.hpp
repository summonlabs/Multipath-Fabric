// Framed wire protocol.
//
// FRAME LAYOUT (little-endian, fixed 24 byte header)
//   [0..4)   magic u32 = 0x5746504D, whose little-endian byte sequence is the
//            ASCII string "MPFW"
//   [4..6)   wire_version u16
//   [6..8)   message_id u16   -- explicit stable numeric id, never an enum ordinal
//   [8..12)  payload_len u32  -- bounded by Limits::max_frame_bytes
//   [12..16) flags u32        -- must be zero
//   [16..24) integrity u64    -- FNV-1a-64 over bytes [0..16) followed by the payload
//   [24..)   payload
//
// The integrity value covers the semantic header (magic, wire version, message
// id, payload length, flags) and the payload, so a corrupted length cannot be
// used to re-frame a stream. The checksum is a structural integrity check, not
// a cryptographic authenticator: Multipath Fabric makes no authenticity claim
// based on it. Raw C++ object layouts are never serialized.
#ifndef MULTIPATH_FABRIC_WIRE_HPP
#define MULTIPATH_FABRIC_WIRE_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/detail/bytes.hpp"
#include "multipath_fabric/explanation.hpp"
#include "multipath_fabric/fabric.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/path_authority.hpp"
#include "multipath_fabric/snapshot.hpp"

namespace multipath_fabric::wire {

// Encoded little-endian, so the first four frame bytes are 'M', 'P', 'F', 'W'.
inline constexpr std::uint32_t frame_magic = 0x5746504DU;
inline constexpr std::size_t frame_header_size = 24;
inline constexpr std::size_t frame_integrity_offset = 16;

// Stable numeric message ids. These values are part of the wire contract and
// are frozen: the test suite asserts each value literally.
//
// The <windows.h> macro named ERROR would otherwise rewrite the ERROR
// enumerator below. The macro is suspended only for the duration of this enum
// declaration and restored immediately afterwards, so no other translation unit
// or header is affected.
#if defined(_WIN32) && defined(ERROR)
#define MPF_WIRE_SUSPENDED_ERROR_MACRO 1
#pragma push_macro("ERROR")
#undef ERROR
#endif

enum class MessageId : std::uint16_t {
  HELLO = 1,
  HELLO_ACK = 2,
  REGISTER_PUBLISHER = 3,
  CREATE_SET = 4,
  ADD_MEMBER = 5,
  REMOVE_MEMBER = 6,
  REVALIDATE_MEMBER = 7,
  REVALIDATE_SET = 8,
  REVOKE_SET = 9,
  RETIRE_SET = 10,
  QUERY_SET = 11,
  SNAPSHOT_REQUEST = 12,
  SNAPSHOT_RESPONSE = 13,
  FENCE_NOTICE = 14,
  RESULT = 15,
  ERROR = 16,
  REPLACE_MEMBER = 17,
  SET_MINIMUM = 18,
  SET_ADMIN_ENABLE = 19,
  SET_ADMIN_DISABLE = 20,
  MEMBER_ADMIN_ENABLE = 21,
  MEMBER_ADMIN_DISABLE = 22,
  EPOCH_ADVANCE = 23,
  LIST_SETS = 24,
  ADVANCE_SET_STATE = 25,
  APPLY_PATH_AUTHORITY = 26,
  REFRESH_PATH = 27,
  ADD_MEMBERS = 28,
  WITHDRAW_MEMBER = 29,
  SET_CONDITIONAL_POLICY = 30,
  SUPERSEDE_SET = 31,
  SHUTDOWN = 32,
  EXPLAIN_SET = 33,
  DECLARE_PATH_AUTHORITY = 34,
};

#if defined(MPF_WIRE_SUSPENDED_ERROR_MACRO)
#pragma pop_macro("ERROR")
#undef MPF_WIRE_SUSPENDED_ERROR_MACRO
#endif

inline constexpr std::uint16_t message_id_min = 1;
inline constexpr std::uint16_t message_id_max = 34;

[[nodiscard]] bool valid_message_id(std::uint16_t raw) noexcept;
[[nodiscard]] std::string_view to_string(MessageId id) noexcept;
[[nodiscard]] std::optional<MessageId> parse_message_id(std::string_view text) noexcept;

// Selector used by ADVANCE_SET_STATE.
enum class SetStateAction : std::uint8_t {
  PUBLISH = 1,
  WITHDRAW = 2,
  COMPLETE_WITHDRAWAL = 3,
};

[[nodiscard]] bool valid_set_state_action(std::uint8_t raw) noexcept;

// One decoded frame.
struct Frame {
  MessageId id = MessageId::HELLO;
  std::vector<std::uint8_t> payload;
};

// Encodes a complete frame. Rejects payloads above p max_frame_bytes.
[[nodiscard]] FabricOutcome encode_frame(MessageId id, const std::vector<std::uint8_t>& payload,
                                         std::uint64_t max_frame_bytes,
                                         std::vector<std::uint8_t>& out);

// Validates and decodes a frame header. The caller states how many header bytes
// are actually readable; a short buffer is rejected before any byte past
// \p header_size is touched. Does not allocate.
[[nodiscard]] FabricOutcome decode_header(const std::uint8_t* header, std::size_t header_size,
                                          std::uint64_t max_frame_bytes, MessageId& id,
                                          std::uint32_t& payload_length);

// Validates the integrity field against the header prefix and the payload.
// \p header_size bounds the readable header bytes exactly as above.
[[nodiscard]] FabricOutcome verify_integrity(const std::uint8_t* header, std::size_t header_size,
                                             const std::vector<std::uint8_t>& payload);

// ---------------------------------------------------------------------------
// Request and response envelopes
// ---------------------------------------------------------------------------

// One decoded request. Only the fields meaningful for the message id are
// encoded or decoded; every other field is ignored on decode.
struct WireRequest {
  MessageId id = MessageId::HELLO;
  MutationContext context;
  AuthorityScope scope;
  SetKey key;
  SetOptions options;
  MultipathSetId set_id;
  MultipathMemberId member_id;
  PathId path_id;
  PathAuthorityGeneration path_authority_generation;
  std::vector<MemberRequest> members;
  std::uint64_t number = 0;
  bool flag = false;
  SetStateAction state_action = SetStateAction::PUBLISH;
  RevocationReason revocation_reason = RevocationReason::ADMINISTRATIVE;
  PathAuthorityState path_state = PathAuthorityState::AUTHORIZED;
  std::string text;
  SnapshotId snapshot_id;
};

struct WireResponse {
  FabricOutcome outcome;
  std::optional<SetSnapshot> snapshot;
  std::optional<SetExplanation> explanation;
  std::vector<MultipathSetId> set_ids;
};

[[nodiscard]] FabricOutcome encode_request(const WireRequest& request,
                                           std::vector<std::uint8_t>& out);
[[nodiscard]] FabricOutcome decode_request(MessageId id, detail::ByteReader& reader,
                                           WireRequest& out);
[[nodiscard]] FabricOutcome encode_response(const WireResponse& response,
                                            std::vector<std::uint8_t>& out);
[[nodiscard]] FabricOutcome decode_response(detail::ByteReader& reader, WireResponse& out);

// ---------------------------------------------------------------------------
// Component codecs (exposed for direct testing)
// ---------------------------------------------------------------------------

[[nodiscard]] FabricOutcome encode_snapshot(detail::ByteWriter& writer, const SetSnapshot& snapshot);
[[nodiscard]] FabricOutcome decode_snapshot(detail::ByteReader& reader, SetSnapshot& snapshot);
[[nodiscard]] FabricOutcome encode_explanation(detail::ByteWriter& writer,
                                               const SetExplanation& explanation);
[[nodiscard]] FabricOutcome decode_explanation(detail::ByteReader& reader,
                                               SetExplanation& explanation);
[[nodiscard]] FabricOutcome encode_outcome(detail::ByteWriter& writer, const FabricOutcome& outcome);
[[nodiscard]] FabricOutcome decode_outcome(detail::ByteReader& reader, FabricOutcome& outcome);

}  // namespace multipath_fabric::wire

#endif  // MULTIPATH_FABRIC_WIRE_HPP
