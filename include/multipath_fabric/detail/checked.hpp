// Checked integer arithmetic helpers.
//
// Multipath Fabric never relies on wrapping arithmetic for generations,
// counts, sizes or offsets. Every increment that could overflow is performed
// through these helpers and an exhausted counter becomes a structured
// rejection instead of silent wraparound.
#ifndef MULTIPATH_FABRIC_DETAIL_CHECKED_HPP
#define MULTIPATH_FABRIC_DETAIL_CHECKED_HPP

#include <cstdint>
#include <limits>
#include <optional>

namespace multipath_fabric::detail {

[[nodiscard]] constexpr bool add_overflows_u64(std::uint64_t a, std::uint64_t b) noexcept {
  return a > (std::numeric_limits<std::uint64_t>::max)() - b;
}

[[nodiscard]] constexpr bool add_overflows_u32(std::uint32_t a, std::uint32_t b) noexcept {
  return a > (std::numeric_limits<std::uint32_t>::max)() - b;
}

[[nodiscard]] constexpr bool multiply_overflows_u64(std::uint64_t a, std::uint64_t b) noexcept {
  if (a == 0 || b == 0) {
    return false;
  }
  return a > (std::numeric_limits<std::uint64_t>::max)() / b;
}

// Returns a + 1, or nullopt when a is already the maximum representable value.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_increment(std::uint64_t a) noexcept {
  if (a == (std::numeric_limits<std::uint64_t>::max)()) {
    return std::nullopt;
  }
  return a + 1;
}

// Returns a + delta, or nullopt on overflow.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_add(std::uint64_t a,
                                                                std::uint64_t delta) noexcept {
  if (add_overflows_u64(a, delta)) {
    return std::nullopt;
  }
  return a + delta;
}

// Returns a * b, or nullopt on overflow.
[[nodiscard]] constexpr std::optional<std::uint64_t> checked_multiply(std::uint64_t a,
                                                                     std::uint64_t b) noexcept {
  if (multiply_overflows_u64(a, b)) {
    return std::nullopt;
  }
  return a * b;
}

// Narrowing helper: succeeds only when the value fits the target type exactly.
[[nodiscard]] constexpr std::optional<std::uint32_t> narrow_u32(std::uint64_t value) noexcept {
  if (value > (std::numeric_limits<std::uint32_t>::max)()) {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(value);
}

[[nodiscard]] constexpr std::optional<std::uint16_t> narrow_u16(std::uint64_t value) noexcept {
  if (value > (std::numeric_limits<std::uint16_t>::max)()) {
    return std::nullopt;
  }
  return static_cast<std::uint16_t>(value);
}

[[nodiscard]] constexpr std::optional<std::uint8_t> narrow_u8(std::uint64_t value) noexcept {
  if (value > (std::numeric_limits<std::uint8_t>::max)()) {
    return std::nullopt;
  }
  return static_cast<std::uint8_t>(value);
}

}  // namespace multipath_fabric::detail

#endif  // MULTIPATH_FABRIC_DETAIL_CHECKED_HPP
