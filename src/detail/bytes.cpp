#include "multipath_fabric/detail/bytes.hpp"

#include <array>

#include "multipath_fabric/detail/checked.hpp"

namespace multipath_fabric::detail {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

}  // namespace

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

std::uint64_t fnv1a64(std::uint64_t seed, const std::uint8_t* data, std::size_t size) noexcept {
  std::uint64_t state = seed;
  for (std::size_t i = 0; i < size; ++i) {
    state = fnv1a64_roll(state, data[i]);
  }
  return state;
}

std::uint64_t fnv1a64(std::string_view data) noexcept {
  return fnv1a64(fnv1a64_offset_basis, reinterpret_cast<const std::uint8_t*>(data.data()),
                 data.size());
}

std::uint32_t fnv1a32(std::uint32_t seed, const std::uint8_t* data, std::size_t size) noexcept {
  std::uint32_t state = seed;
  for (std::size_t i = 0; i < size; ++i) {
    state ^= static_cast<std::uint32_t>(data[i]);
    state *= 16777619U;
  }
  return state;
}

std::string Digest128::to_hex() const {
  std::array<char, 32> chars{};
  for (int i = 0; i < 16; ++i) {
    const unsigned shift = static_cast<unsigned>(60 - 4 * i);
    const std::uint64_t nibble = (high >> shift) & 0xFULL;
    chars[static_cast<std::size_t>(i)] = kHexDigits[nibble];
  }
  for (int i = 0; i < 16; ++i) {
    const unsigned shift = static_cast<unsigned>(60 - 4 * i);
    const std::uint64_t nibble = (low >> shift) & 0xFULL;
    chars[static_cast<std::size_t>(16 + i)] = kHexDigits[nibble];
  }
  return std::string(chars.data(), chars.size());
}

// ---------------------------------------------------------------------------
// DigestBuilder
// ---------------------------------------------------------------------------

void DigestBuilder::absorb_byte(std::uint8_t value) noexcept {
  lane_a_ = fnv1a64_roll(lane_a_, value);
  // The second lane mixes the byte with a position-independent odd constant so
  // that the two lanes do not degenerate into the same value.
  lane_b_ ^= static_cast<std::uint64_t>(value) + 0x9E3779B97F4A7C15ULL;
  lane_b_ *= digest64_prime_b;
  lane_b_ = (lane_b_ << 13) | (lane_b_ >> 51);
}

void DigestBuilder::absorb_bytes(std::string_view value) noexcept {
  absorb_u64(value.size());
  for (const char ch : value) {
    absorb_byte(static_cast<std::uint8_t>(ch));
  }
}

void DigestBuilder::absorb_u8(std::uint8_t value) noexcept { absorb_byte(value); }

void DigestBuilder::absorb_u16(std::uint16_t value) noexcept {
  absorb_byte(static_cast<std::uint8_t>(value & 0xFFU));
  absorb_byte(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void DigestBuilder::absorb_u32(std::uint32_t value) noexcept {
  for (int i = 0; i < 4; ++i) {
    absorb_byte(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU));
  }
}

void DigestBuilder::absorb_u64(std::uint64_t value) noexcept {
  for (int i = 0; i < 8; ++i) {
    absorb_byte(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU));
  }
}

void DigestBuilder::absorb_i64(std::int64_t value) noexcept {
  absorb_u64(static_cast<std::uint64_t>(value));
}

void DigestBuilder::absorb_bool(bool value) noexcept { absorb_byte(value ? 1U : 0U); }

void DigestBuilder::absorb_string(std::string_view value) noexcept { absorb_bytes(value); }

void DigestBuilder::absorb_tagged(std::string_view tag, std::string_view value) noexcept {
  absorb_bytes(tag);
  absorb_bytes(value);
}

Digest128 DigestBuilder::finish() const noexcept {
  Digest128 result;
  result.high = lane_a_;
  result.low = lane_b_;
  // Avalanche both lanes so that small structural differences spread across
  // the whole rendered value.
  result.high ^= result.high >> 33;
  result.high *= 0xFF51AFD7ED558CCDULL;
  result.high ^= result.high >> 33;
  result.low ^= result.low >> 29;
  result.low *= 0xC4CEB9FE1A85EC53ULL;
  result.low ^= result.low >> 32;
  result.high ^= result.low;
  return result;
}

// ---------------------------------------------------------------------------
// ByteWriter
// ---------------------------------------------------------------------------

bool ByteWriter::reserve(std::size_t count) noexcept {
  if (!ok_) {
    return false;
  }
  if (count > limit_ || buffer_.size() > limit_ - count) {
    ok_ = false;
    return false;
  }
  return true;
}

void ByteWriter::raw(const std::uint8_t* data, std::size_t size) noexcept {
  if (!reserve(size)) {
    return;
  }
  buffer_.insert(buffer_.end(), data, data + size);
}

void ByteWriter::u8(std::uint8_t value) noexcept { raw(&value, 1); }

void ByteWriter::u16(std::uint16_t value) noexcept {
  const std::array<std::uint8_t, 2> bytes{static_cast<std::uint8_t>(value & 0xFFU),
                                          static_cast<std::uint8_t>((value >> 8U) & 0xFFU)};
  raw(bytes.data(), bytes.size());
}

void ByteWriter::u32(std::uint32_t value) noexcept {
  std::array<std::uint8_t, 4> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU);
  }
  raw(bytes.data(), bytes.size());
}

void ByteWriter::u64(std::uint64_t value) noexcept {
  std::array<std::uint8_t, 8> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xFFU);
  }
  raw(bytes.data(), bytes.size());
}

void ByteWriter::i64(std::int64_t value) noexcept { u64(static_cast<std::uint64_t>(value)); }

void ByteWriter::boolean(bool value) noexcept { u8(value ? 1U : 0U); }

void ByteWriter::string(std::string_view value, std::size_t bound) noexcept {
  if (value.size() > bound) {
    ok_ = false;
    return;
  }
  const auto length = narrow_u32(value.size());
  if (!length.has_value()) {
    ok_ = false;
    return;
  }
  u32(*length);
  raw(reinterpret_cast<const std::uint8_t*>(value.data()), value.size());
}

// ---------------------------------------------------------------------------
// ByteReader
// ---------------------------------------------------------------------------

bool ByteReader::require(std::size_t count) noexcept {
  if (!ok_) {
    return false;
  }
  if (count > size_ - offset_) {
    ok_ = false;
    return false;
  }
  return true;
}

std::optional<std::uint8_t> ByteReader::u8() noexcept {
  if (!require(1)) {
    return std::nullopt;
  }
  return data_[offset_++];
}

std::optional<std::uint16_t> ByteReader::u16() noexcept {
  if (!require(2)) {
    return std::nullopt;
  }
  const std::uint16_t value = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(data_[offset_]) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(data_[offset_ + 1]) << 8U));
  offset_ += 2;
  return value;
}

std::optional<std::uint32_t> ByteReader::u32() noexcept {
  if (!require(4)) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data_[offset_ + static_cast<std::size_t>(i)])
             << static_cast<unsigned>(8 * i);
  }
  offset_ += 4;
  return value;
}

std::optional<std::uint64_t> ByteReader::u64() noexcept {
  if (!require(8)) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data_[offset_ + static_cast<std::size_t>(i)])
             << static_cast<unsigned>(8 * i);
  }
  offset_ += 8;
  return value;
}

std::optional<std::int64_t> ByteReader::i64() noexcept {
  const auto value = u64();
  if (!value.has_value()) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(*value);
}

std::optional<bool> ByteReader::boolean() noexcept {
  const auto value = u8();
  if (!value.has_value()) {
    return std::nullopt;
  }
  if (*value > 1U) {
    ok_ = false;
    return std::nullopt;
  }
  return *value == 1U;
}

std::optional<std::string> ByteReader::string(std::size_t bound) noexcept {
  const auto length = u32();
  if (!length.has_value()) {
    return std::nullopt;
  }
  if (*length > bound || !require(*length)) {
    ok_ = false;
    return std::nullopt;
  }
  std::string value(reinterpret_cast<const char*>(data_ + offset_), *length);
  offset_ += *length;
  return value;
}

bool ByteReader::raw(std::uint8_t* out, std::size_t count) noexcept {
  if (!require(count)) {
    return false;
  }
  for (std::size_t i = 0; i < count; ++i) {
    out[i] = data_[offset_ + i];
  }
  offset_ += count;
  return true;
}

std::optional<std::string_view> ByteReader::raw_view(std::size_t count) noexcept {
  if (!require(count)) {
    return std::nullopt;
  }
  std::string_view view(reinterpret_cast<const char*>(data_ + offset_), count);
  offset_ += count;
  return view;
}

}  // namespace multipath_fabric::detail
