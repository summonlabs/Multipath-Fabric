// Deterministic little-endian byte codec and non-cryptographic checksums.
//
// Every Multipath Fabric persistence record and every wire payload is produced
// through these primitives. The encoding is explicitly little-endian and
// length-prefixed; raw C++ object layouts are never serialized.
//
// The checksum helpers are structural integrity checksums. They detect
// accidental corruption and truncation. They are NOT cryptographic and
// Multipath Fabric makes no authenticity claim based on them.
#ifndef MULTIPATH_FABRIC_DETAIL_BYTES_HPP
#define MULTIPATH_FABRIC_DETAIL_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace multipath_fabric::detail {

// ---------------------------------------------------------------------------
// Checksums (non-cryptographic)
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t fnv1a64_offset_basis = 14695981039346656037ULL;
inline constexpr std::uint64_t fnv1a64_prime = 1099511628211ULL;

// Second, independent 64-bit lane used to build the 128-bit structural digest.
inline constexpr std::uint64_t digest64_offset_basis_b = 0x9E3779B97F4A7C15ULL;
inline constexpr std::uint64_t digest64_prime_b = 0x100000001B3ULL /* same prime */;

[[nodiscard]] std::uint64_t fnv1a64(std::uint64_t seed, const std::uint8_t* data,
                                   std::size_t size) noexcept;
[[nodiscard]] std::uint64_t fnv1a64(std::string_view data) noexcept;
[[nodiscard]] std::uint32_t fnv1a32(std::uint32_t seed, const std::uint8_t* data,
                                   std::size_t size) noexcept;

inline constexpr std::uint64_t fnv1a64_roll(std::uint64_t state, std::uint8_t byte) noexcept {
  state ^= static_cast<std::uint64_t>(byte);
  state *= fnv1a64_prime;
  return state;
}

// 128-bit structural digest rendered as 32 lowercase hex characters.
struct Digest128 {
  std::uint64_t high = 0;
  std::uint64_t low = 0;

  [[nodiscard]] std::string to_hex() const;
  [[nodiscard]] bool operator==(const Digest128& other) const noexcept = default;
  [[nodiscard]] bool operator<(const Digest128& other) const noexcept {
    return high != other.high ? high < other.high : low < other.low;
  }
  [[nodiscard]] bool is_zero() const noexcept { return high == 0 && low == 0; }
};

// Incremental digest builder. Bytes are absorbed in call order; callers are
// responsible for feeding a canonical byte sequence.
class DigestBuilder {
 public:
  DigestBuilder() noexcept
      : lane_a_(fnv1a64_offset_basis), lane_b_(digest64_offset_basis_b) {}

  void absorb_byte(std::uint8_t value) noexcept;
  void absorb_bytes(std::string_view value) noexcept;
  void absorb_u8(std::uint8_t value) noexcept;
  void absorb_u16(std::uint16_t value) noexcept;
  void absorb_u32(std::uint32_t value) noexcept;
  void absorb_u64(std::uint64_t value) noexcept;
  void absorb_i64(std::int64_t value) noexcept;
  void absorb_bool(bool value) noexcept;
  // Length-prefixed: the length is absorbed first so that distinct field
  // splits cannot collide.
  void absorb_string(std::string_view value) noexcept;
  void absorb_tagged(std::string_view tag, std::string_view value) noexcept;

  [[nodiscard]] Digest128 finish() const noexcept;

 private:
  std::uint64_t lane_a_;
  std::uint64_t lane_b_;
};

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

// Bounded byte writer. Every write is checked against an explicit limit so a
// producer can never emit an unbounded record.
class ByteWriter {
 public:
  explicit ByteWriter(std::size_t limit) : limit_(limit) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] bool overflowed() const noexcept { return !ok_; }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  [[nodiscard]] const std::vector<std::uint8_t>& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::vector<std::uint8_t> take() noexcept { return std::move(buffer_); }

  void u8(std::uint8_t value) noexcept;
  void u16(std::uint16_t value) noexcept;
  void u32(std::uint32_t value) noexcept;
  void u64(std::uint64_t value) noexcept;
  void i64(std::int64_t value) noexcept;
  void boolean(bool value) noexcept;
  // Length-prefixed string with an explicit per-string bound.
  void string(std::string_view value, std::size_t bound) noexcept;
  void raw(const std::uint8_t* data, std::size_t size) noexcept;

 private:
  [[nodiscard]] bool reserve(std::size_t count) noexcept;

  std::vector<std::uint8_t> buffer_;
  std::size_t limit_;
  bool ok_ = true;
};

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

// Bounded byte reader with strict trailing-byte detection.
class ByteReader {
 public:
  ByteReader(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

  [[nodiscard]] bool ok() const noexcept { return ok_; }
  [[nodiscard]] bool failed() const noexcept { return !ok_; }
  [[nodiscard]] std::size_t remaining() const noexcept { return ok_ ? size_ - offset_ : 0; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }
  [[nodiscard]] bool at_end() const noexcept { return ok_ && offset_ == size_; }

  [[nodiscard]] std::optional<std::uint8_t> u8() noexcept;
  [[nodiscard]] std::optional<std::uint16_t> u16() noexcept;
  [[nodiscard]] std::optional<std::uint32_t> u32() noexcept;
  [[nodiscard]] std::optional<std::uint64_t> u64() noexcept;
  [[nodiscard]] std::optional<std::int64_t> i64() noexcept;
  [[nodiscard]] std::optional<bool> boolean() noexcept;
  // Reads a length-prefixed string, rejecting lengths above p bound.
  [[nodiscard]] std::optional<std::string> string(std::size_t bound) noexcept;
  [[nodiscard]] bool raw(std::uint8_t* out, std::size_t count) noexcept;
  [[nodiscard]] std::optional<std::string_view> raw_view(std::size_t count) noexcept;

  void fail() noexcept { ok_ = false; }

 private:
  [[nodiscard]] bool require(std::size_t count) noexcept;

  const std::uint8_t* data_;
  std::size_t size_;
  std::size_t offset_ = 0;
  bool ok_ = true;
};

}  // namespace multipath_fabric::detail

#endif  // MULTIPATH_FABRIC_DETAIL_BYTES_HPP
