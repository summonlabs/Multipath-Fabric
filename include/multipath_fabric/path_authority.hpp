// Path Authority consumption surface.
//
// Path Authority owns exact path legality. Multipath Fabric never infers it.
// It consumes, for one exact path identity, the current Path Authority
// generation and the current legality state, and binds both into the member.
//
// If the bound generation is not the generation Path Authority currently
// reports, the member is stale regardless of the state -- a historical
// AUTHORIZED result never counts.
#ifndef MULTIPATH_FABRIC_PATH_AUTHORITY_HPP
#define MULTIPATH_FABRIC_PATH_AUTHORITY_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string_view>

#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"

namespace multipath_fabric {

enum class PathAuthorityState : std::uint8_t {
  AUTHORIZED = 1,
  CONDITIONALLY_AUTHORIZED = 2,
  REVALIDATION_REQUIRED = 3,
  REJECTED = 4,
  REVOKED = 5,
  STALE = 6,
  RETIRED = 7,
};

[[nodiscard]] std::string_view to_string(PathAuthorityState state) noexcept;
[[nodiscard]] std::optional<PathAuthorityState> parse_path_authority_state(
    std::string_view text) noexcept;
[[nodiscard]] bool valid_path_authority_state(std::uint8_t raw) noexcept;

// The exact view Multipath Fabric consumes for one path.
struct PathAuthorityView {
  PathId path;
  PathAuthorityGeneration generation;
  PathAuthorityState state;

  [[nodiscard]] friend bool operator==(const PathAuthorityView& a,
                                       const PathAuthorityView& b) noexcept {
    return a.path == b.path && a.generation == b.generation && a.state == b.state;
  }
};

// Integration seam. A deployment supplies an implementation backed by the real
// Path Authority runtime. Multipath Fabric calls lookup() outside its own locks
// and never mutates the source.
class PathAuthoritySource {
 public:
  PathAuthoritySource() = default;
  PathAuthoritySource(const PathAuthoritySource&) = delete;
  PathAuthoritySource& operator=(const PathAuthoritySource&) = delete;
  PathAuthoritySource(PathAuthoritySource&&) = delete;
  PathAuthoritySource& operator=(PathAuthoritySource&&) = delete;
  virtual ~PathAuthoritySource() = default;

  // Returns std::nullopt when Path Authority has no record for this exact path.
  [[nodiscard]] virtual std::optional<PathAuthorityView> lookup(const PathId& path) const = 0;
};

// Reference directory adapter.
//
// This is a self-contained reference source used by tests, examples and
// synthetic scale exercises. It is NOT the Path Authority runtime; it exposes
// the same consumption surface so that integration code is exercised in
// closure. A production deployment substitutes the real Path Authority client.
class PathAuthorityDirectory final : public PathAuthoritySource {
 public:
  PathAuthorityDirectory() = default;

  // Registers or replaces the exact view for a path.
  void set(PathAuthorityView view);
  void set(PathId path, PathAuthorityGeneration generation, PathAuthorityState state);

  // Advances the generation by one and applies a new state. Returns the new
  // generation, or nullopt when the counter is exhausted.
  [[nodiscard]] std::optional<PathAuthorityGeneration> advance(const PathId& path,
                                                               PathAuthorityState state);

  // Changes only the state, leaving the generation unchanged.
  [[nodiscard]] bool set_state(const PathId& path, PathAuthorityState state);

  [[nodiscard]] bool erase(const PathId& path);

  [[nodiscard]] std::optional<PathAuthorityView> lookup(const PathId& path) const override;

  [[nodiscard]] std::size_t size() const;

 private:
  mutable std::mutex mutex_;
  std::map<PathId, PathAuthorityView> entries_;
};

// Classifies a member's Path Authority inputs.
//
//   * no view                       -> PATH_AUTHORITY_UNKNOWN
//   * view.generation != bound      -> STALE_PATH_AUTHORITY (generation wins)
//   * AUTHORIZED                    -> CURRENT
//   * CONDITIONALLY_AUTHORIZED      -> CURRENT when the set policy permits it,
//                                      otherwise PATH_CONDITIONALLY_NOT_PERMITTED
//   * REVALIDATION_REQUIRED         -> PATH_REVALIDATION_REQUIRED
//   * REJECTED                      -> PATH_REJECTED
//   * REVOKED                       -> PATH_REVOKED
//   * STALE                         -> PATH_STALE
//   * RETIRED                       -> PATH_RETIRED
[[nodiscard]] MemberCurrentness classify_path_authority(
    const std::optional<PathAuthorityView>& view, PathAuthorityGeneration bound_generation,
    bool conditional_authority_permitted) noexcept;

}  // namespace multipath_fabric

#endif  // MULTIPATH_FABRIC_PATH_AUTHORITY_HPP
