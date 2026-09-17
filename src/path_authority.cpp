#include "multipath_fabric/path_authority.hpp"

namespace multipath_fabric {

std::string_view to_string(PathAuthorityState state) noexcept {
  switch (state) {
    case PathAuthorityState::AUTHORIZED: return "AUTHORIZED";
    case PathAuthorityState::CONDITIONALLY_AUTHORIZED: return "CONDITIONALLY_AUTHORIZED";
    case PathAuthorityState::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    case PathAuthorityState::REJECTED: return "REJECTED";
    case PathAuthorityState::REVOKED: return "REVOKED";
    case PathAuthorityState::STALE: return "STALE";
    case PathAuthorityState::RETIRED: return "RETIRED";
  }
  return "<invalid-path-authority-state>";
}

std::optional<PathAuthorityState> parse_path_authority_state(std::string_view text) noexcept {
  for (std::uint8_t raw = 1; raw <= 7; ++raw) {
    const auto candidate = static_cast<PathAuthorityState>(raw);
    if (to_string(candidate) == text) {
      return candidate;
    }
  }
  return std::nullopt;
}

bool valid_path_authority_state(std::uint8_t raw) noexcept { return raw >= 1 && raw <= 7; }

void PathAuthorityDirectory::set(PathAuthorityView view) {
  std::lock_guard<std::mutex> guard(mutex_);
  entries_[view.path] = std::move(view);
}

void PathAuthorityDirectory::set(PathId path, PathAuthorityGeneration generation,
                                 PathAuthorityState state) {
  std::lock_guard<std::mutex> guard(mutex_);
  PathAuthorityView view;
  view.path = std::move(path);
  view.generation = generation;
  view.state = state;
  entries_[view.path] = std::move(view);
}

std::optional<PathAuthorityGeneration> PathAuthorityDirectory::advance(
    const PathId& path, PathAuthorityState state) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto it = entries_.find(path);
  PathAuthorityGeneration current;
  if (it == entries_.end()) {
    current = PathAuthorityGeneration::first();
  } else {
    const auto advanced = it->second.generation.next();
    if (!advanced.has_value()) {
      return std::nullopt;
    }
    current = *advanced;
  }
  PathAuthorityView view;
  view.path = path;
  view.generation = current;
  view.state = state;
  entries_[path] = std::move(view);
  return current;
}

bool PathAuthorityDirectory::set_state(const PathId& path, PathAuthorityState state) {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto it = entries_.find(path);
  if (it == entries_.end()) {
    return false;
  }
  it->second.state = state;
  return true;
}

bool PathAuthorityDirectory::erase(const PathId& path) {
  std::lock_guard<std::mutex> guard(mutex_);
  return entries_.erase(path) > 0;
}

std::optional<PathAuthorityView> PathAuthorityDirectory::lookup(const PathId& path) const {
  std::lock_guard<std::mutex> guard(mutex_);
  const auto it = entries_.find(path);
  if (it == entries_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::size_t PathAuthorityDirectory::size() const {
  std::lock_guard<std::mutex> guard(mutex_);
  return entries_.size();
}

MemberCurrentness classify_path_authority(const std::optional<PathAuthorityView>& view,
                                          PathAuthorityGeneration bound_generation,
                                          bool conditional_authority_permitted) noexcept {
  if (!view.has_value()) {
    return MemberCurrentness::PATH_AUTHORITY_UNKNOWN;
  }
  // Generation currency is checked first. A historical AUTHORIZED result for a
  // superseded generation never counts as usable.
  if (view->generation != bound_generation) {
    return MemberCurrentness::STALE_PATH_AUTHORITY;
  }
  switch (view->state) {
    case PathAuthorityState::AUTHORIZED:
      return MemberCurrentness::CURRENT;
    case PathAuthorityState::CONDITIONALLY_AUTHORIZED:
      return conditional_authority_permitted ? MemberCurrentness::CURRENT
                                             : MemberCurrentness::PATH_CONDITIONALLY_NOT_PERMITTED;
    case PathAuthorityState::REVALIDATION_REQUIRED:
      return MemberCurrentness::PATH_REVALIDATION_REQUIRED;
    case PathAuthorityState::REJECTED:
      return MemberCurrentness::PATH_REJECTED;
    case PathAuthorityState::REVOKED:
      return MemberCurrentness::PATH_REVOKED;
    case PathAuthorityState::STALE:
      return MemberCurrentness::PATH_STALE;
    case PathAuthorityState::RETIRED:
      return MemberCurrentness::PATH_RETIRED;
  }
  return MemberCurrentness::PATH_AUTHORITY_UNKNOWN;
}

}  // namespace multipath_fabric
