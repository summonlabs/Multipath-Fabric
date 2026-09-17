// Versioned, integrity-checked persistence.
//
// FORMAT (little-endian, deterministic)
//   magic         8 bytes  "MPFSTOR\0"
//   format        u32      persistence_format_version
//   reserved      u32      must be zero
//   payload_len   u64      bounded by Limits::max_persistence_record_bytes
//   payload       payload_len bytes
//   checksum      u64      FNV-1a-64 over the 24 header bytes followed by the
//                          payload; detects corruption and truncation
//
// The payload carries an internal payload digest and an explicit record count.
// Decoding rejects: bad magic, unsupported version, non-zero reserved field,
// truncated header, truncated payload, checksum mismatch, trailing bytes,
// duplicate set identity, duplicate set key, duplicate member, dangling member,
// impossible generations, invalid thresholds, malformed enumerators, absurd
// counts and records larger than the configured bound.
//
// The checksum is a structural integrity check. It is not cryptographic and
// Multipath Fabric makes no authenticity claim based on it.
#ifndef MULTIPATH_FABRIC_PERSISTENCE_HPP
#define MULTIPATH_FABRIC_PERSISTENCE_HPP

#include <cstdint>
#include <string_view>

#include "multipath_fabric/version.hpp"

namespace multipath_fabric {

inline constexpr std::string_view store_magic = "MPFSTOR";
inline constexpr std::size_t store_magic_size = 8;
inline constexpr std::size_t store_header_size = 24;

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_PERSISTENCE_HPP
