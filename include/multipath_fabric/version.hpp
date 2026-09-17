// Multipath Fabric 1.0.0 -- Summon Software Labs.
//
// Central version declaration. The library version, the installed CMake package
// version and the CLI version are all derived from this single header so that
// they cannot drift apart.
#ifndef MULTIPATH_FABRIC_VERSION_HPP
#define MULTIPATH_FABRIC_VERSION_HPP

#include <cstdint>
#include <string_view>

namespace multipath_fabric {

inline constexpr std::uint32_t version_major = 1;
inline constexpr std::uint32_t version_minor = 0;
inline constexpr std::uint32_t version_patch = 0;

// Semantic version of the library, the CMake package and the CLI.
inline constexpr std::string_view version_string = "1.0.0";

// Persistence format version. Versioned independently from the library version
// because the on-disk encoding has its own compatibility contract.
inline constexpr std::uint32_t persistence_format_version = 1;

// Wire protocol version. Versioned independently from the library version
// because the framed transport has its own compatibility contract.
inline constexpr std::uint16_t wire_protocol_version = 1;

// Stable textual product identity used by the CLI and by diagnostics.
inline constexpr std::string_view product_name = "Multipath Fabric";

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_VERSION_HPP
