#include "multipath_fabric/detail/records.hpp"

#include <sstream>

namespace multipath_fabric {
namespace detail {

std::uint64_t SetRecord::recompute_usable_members() const noexcept {
  std::uint64_t count = 0;
  for (const auto& entry : members) {
    if (entry.second.usable()) {
      ++count;
    }
  }
  return count;
}

Digest128 compute_member_digest(const MemberRecord& record) {
  DigestBuilder builder;
  builder.absorb_tagged("domain", "multipath-fabric.member.v1");
  builder.absorb_tagged("member_id", record.id.view());
  builder.absorb_tagged("path_id", record.path_id.view());
  builder.absorb_tagged("path_authority_generation",
                        std::to_string(record.bound_authority_generation.value()));
  builder.absorb_tagged("member_generation", std::to_string(record.generation.value()));
  builder.absorb_u8(static_cast<std::uint8_t>(record.lifecycle));
  builder.absorb_u8(static_cast<std::uint8_t>(record.currentness));
  builder.absorb_bool(record.admin_enabled);
  builder.absorb_tagged("predecessor",
                        record.predecessor.has_value() ? record.predecessor->view()
                                                      : std::string_view("-"));
  builder.absorb_tagged("successor", record.successor.has_value() ? record.successor->view()
                                                                 : std::string_view("-"));
  return builder.finish();
}

Digest128 compute_set_digest(const SetRecord& record) {
  DigestBuilder builder;
  builder.absorb_tagged("domain", "multipath-fabric.set.v1");
  builder.absorb_tagged("set_id", record.id.view());
  builder.absorb_tagged("fabric", record.key.fabric.view());
  builder.absorb_tagged("namespace", record.key.name_space.view());
  builder.absorb_tagged("name", record.key.name.view());
  builder.absorb_tagged("set_generation", std::to_string(record.generation.value()));
  builder.absorb_tagged("membership_generation",
                        std::to_string(record.membership_generation.value()));
  builder.absorb_tagged("authority_generation",
                        std::to_string(record.authority_generation.value()));
  builder.absorb_u8(static_cast<std::uint8_t>(record.lifecycle));
  builder.absorb_u8(static_cast<std::uint8_t>(record.currentness));
  builder.absorb_bool(record.admin_enabled);
  builder.absorb_tagged("minimum_usable_members",
                        std::to_string(record.minimum_usable_members));
  builder.absorb_bool(record.conditional_authority_permitted);
  builder.absorb_tagged("governing_epoch", std::to_string(record.governing_epoch.value()));
  builder.absorb_tagged("superseded_by", record.superseded_by.has_value()
                                             ? record.superseded_by->view()
                                             : std::string_view("-"));
  builder.absorb_tagged("supersedes", record.supersedes.has_value() ? record.supersedes->view()
                                                                    : std::string_view("-"));
  if (record.revocation.has_value()) {
    builder.absorb_bool(true);
    builder.absorb_u8(static_cast<std::uint8_t>(record.revocation->reason));
    builder.absorb_tagged("revocation_detail", record.revocation->detail);
    builder.absorb_tagged("revocation_generation",
                          std::to_string(record.revocation->generation.value()));
  } else {
    builder.absorb_bool(false);
  }
  // Canonical membership: the map is already ordered by PathId.
  builder.absorb_tagged("member_count", std::to_string(record.members.size()));
  for (const auto& entry : record.members) {
    const MemberRecord& member = entry.second;
    builder.absorb_tagged("member", member.id.view());
    builder.absorb_tagged("member_path", member.path_id.view());
    builder.absorb_tagged("member_path_authority_generation",
                          std::to_string(member.bound_authority_generation.value()));
    builder.absorb_tagged("member_generation", std::to_string(member.generation.value()));
    builder.absorb_u8(static_cast<std::uint8_t>(member.lifecycle));
    builder.absorb_u8(static_cast<std::uint8_t>(member.currentness));
    builder.absorb_bool(member.admin_enabled);
  }
  return builder.finish();
}

Digest128 fingerprint_request(std::string_view operation,
                              const std::vector<std::string>& fields) {
  DigestBuilder builder;
  builder.absorb_tagged("domain", "multipath-fabric.request.v1");
  builder.absorb_tagged("operation", operation);
  builder.absorb_tagged("field_count", std::to_string(fields.size()));
  for (const auto& field : fields) {
    builder.absorb_tagged("field", field);
  }
  return builder.finish();
}

}  // namespace detail

std::string SetKey::render() const {
  std::ostringstream stream;
  stream << (fabric.valid() ? fabric.view() : std::string_view("<unset>")) << '/'
         << (name_space.valid() ? name_space.view() : std::string_view("<unset>")) << '/'
         << (name.valid() ? name.view() : std::string_view("<unset>"));
  return stream.str();
}

namespace detail {

std::string HistoryEntry::render() const {
  std::ostringstream stream;
  stream << "gen=" << set_generation.value() << " event=" << to_string(event)
         << " cause=" << to_string(cause) << " publisher=" << publisher.view()
         << " epoch=" << epoch.value();
  if (member_id.has_value()) {
    stream << " member=" << member_id->view();
  }
  if (path_id.has_value()) {
    stream << " path=" << path_id->view();
  }
  if (!summary.empty()) {
    stream << " summary=\"" << summary << "\"";
  }
  return stream.str();
}

}  // namespace detail
}  // namespace multipath_fabric
