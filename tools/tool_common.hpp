// Shared helpers for the Multipath Fabric process tools.
//
// INTERNAL to the tools. Not installed.
#ifndef MULTIPATH_FABRIC_TOOLS_TOOL_COMMON_HPP
#define MULTIPATH_FABRIC_TOOLS_TOOL_COMMON_HPP

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "multipath_fabric/multipath_fabric.hpp"

namespace mpf_tool {

// Deterministic command line parsing: "--name value" and "--flag".
class Arguments {
 public:
  Arguments(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
      tokens_.emplace_back(argv[i]);
    }
  }

  [[nodiscard]] const std::vector<std::string>& tokens() const noexcept { return tokens_; }

  [[nodiscard]] std::size_t size() const noexcept { return tokens_.size(); }
  [[nodiscard]] const std::string& at(std::size_t index) const { return tokens_[index]; }

  // Boolean options never consume the following token.
  [[nodiscard]] static bool is_boolean_option(const std::string& token) {
    return token == "--admin-disabled" || token == "--conditional" ||
           token == "--no-publish" || token == "--no-autosave" || token == "--quiet" ||
           token == "--help";
  }

  // Positional arguments in order, ignoring options and the values that consume
  // them. This lets options appear before or after the command.
  [[nodiscard]] std::vector<std::string> positionals() const {
    std::vector<std::string> result;
    for (std::size_t i = 0; i < tokens_.size(); ++i) {
      if (tokens_[i].size() >= 2 && tokens_[i][0] == '-' && tokens_[i][1] == '-') {
        if (!is_boolean_option(tokens_[i]) && i + 1 < tokens_.size()) {
          ++i;
        }
        continue;
      }
      result.push_back(tokens_[i]);
    }
    return result;
  }

  [[nodiscard]] std::optional<std::string> value(const std::string& name) const {
    for (std::size_t i = 0; i + 1 < tokens_.size(); ++i) {
      if (tokens_[i] == name) {
        return tokens_[i + 1];
      }
    }
    return std::nullopt;
  }

  [[nodiscard]] bool has(const std::string& name) const {
    for (const auto& token : tokens_) {
      if (token == name) {
        return true;
      }
    }
    return false;
  }

  [[nodiscard]] std::uint64_t number(const std::string& name, std::uint64_t fallback) const {
    const auto text = value(name);
    if (!text.has_value()) {
      return fallback;
    }
    std::uint64_t value = 0;
    for (const char c : *text) {
      if (c < '0' || c > '9') {
        return fallback;
      }
      value = value * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    return value;
  }

  [[nodiscard]] std::string text(const std::string& name, const std::string& fallback) const {
    const auto found = value(name);
    return found.has_value() ? *found : fallback;
  }

 private:
  std::vector<std::string> tokens_;
};

// Writes a small file atomically enough for test coordination: write, flush,
// close. Used for readiness announcement files, never as durable storage.
[[nodiscard]] inline bool write_announcement(const std::string& path,
                                             const std::string& content) {
  if (path.empty()) {
    return false;
  }
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  if (!stream) {
    return false;
  }
  stream << content;
  stream.flush();
  return static_cast<bool>(stream);
}

inline void print_outcome(const multipath_fabric::FabricOutcome& outcome) {
  std::cout << outcome.render() << '\n';
}

}  // namespace mpf_tool

#endif  // MULTIPATH_FABRIC_TOOLS_TOOL_COMMON_HPP
