// mpf -- the Multipath Fabric command line interface.
//
// Deterministic, script-friendly output: one record per line, no timestamps, no
// terminal control sequences. Exit codes: 0 accepted, 1 rejected by the
// coordinator, 2 malformed invocation, 3 transport failure.
#include <iostream>
#include <sstream>

#include "tool_common.hpp"

namespace {

using multipath_fabric::FabricOutcome;
using multipath_fabric::OutcomeCode;

constexpr int kExitOk = 0;
constexpr int kExitRejected = 1;
constexpr int kExitUsage = 2;
constexpr int kExitTransport = 3;

int report(const FabricOutcome& outcome, bool transport_failure) {
  mpf_tool::print_outcome(outcome);
  if (transport_failure) {
    return kExitTransport;
  }
  return outcome.succeeded() ? kExitOk : kExitRejected;
}

void usage() {
  std::cout
      << "usage: mpf [--host HOST] [--port N] [--publisher ID] [--boot ID]\n"
         "           [--fabric F] [--namespace NS] <command> [arguments]\n"
         "\n"
         "commands:\n"
         "  version\n"
         "  limits\n"
         "  set create --name NAME [--minimum K] [--admin-disabled] [--conditional]\n"
         "  set show SETID\n"
         "  set list\n"
         "  set publish SETID\n"
         "  set withdraw SETID [--reason TEXT]\n"
         "  set complete-withdrawal SETID\n"
         "  set minimum SETID K\n"
         "  set policy SETID authorized|conditional\n"
         "  set enable SETID | set disable SETID\n"
         "  set revalidate SETID\n"
         "  set revoke SETID REASON [--detail TEXT]\n"
         "  set retire SETID [--reason TEXT]\n"
         "  set supersede PREDECESSOR SUCCESSOR\n"
         "  member add SETID PATH GENERATION\n"
         "  member add-bulk SETID PATH:GENERATION [PATH:GENERATION ...]\n"
         "  member remove SETID MEMBERID [--reason TEXT]\n"
         "  member withdraw SETID MEMBERID [--reason TEXT]\n"
         "  member revalidate SETID MEMBERID\n"
         "  member replace SETID MEMBERID PATH GENERATION [--reason TEXT]\n"
         "  member enable SETID MEMBERID | member disable SETID MEMBERID\n"
         "  path declare PATH GENERATION STATE\n"
         "  path refresh PATH\n"
         "  authority\n"
         "  epoch advance\n"
         "  snapshot SETID [SNAPSHOTID]\n"
         "  diff SETID\n"
         "  explain SETID\n"
         "  store inspect PATH\n";
}

[[nodiscard]] std::string positional_at(const std::vector<std::string>& positional,
                                       std::size_t index) {
  return index < positional.size() ? positional[index] : std::string();
}

[[nodiscard]] std::size_t positional_size(const std::vector<std::string>& positional) {
  return positional.size();
}

[[nodiscard]] bool is_transport_failure(OutcomeCode code) {
  switch (code) {
    case OutcomeCode::FRAMING_ERROR:
    case OutcomeCode::INTEGRITY_ERROR:
    case OutcomeCode::UNSUPPORTED_WIRE_VERSION:
    case OutcomeCode::SESSION_TIMEOUT:
    case OutcomeCode::SESSION_LIMIT:
      return true;
    default:
      return false;
  }
}

}  // namespace

// One interactive CLI session: an open connection plus the identity and scope
// the command will act under.
struct CliSession {
  multipath_fabric::MultipathFabricClient client;
  multipath_fabric::PublisherId publisher;
  multipath_fabric::WorkerBootId boot;
  multipath_fabric::AuthorityScope scope;
  std::uint64_t attempts = 0;

  [[nodiscard]] multipath_fabric::MutationContext next_context() {
    multipath_fabric::MutationContext context;
    context.publisher = publisher;
    context.worker_boot = boot;
    context.attempt = multipath_fabric::MutationAttemptId::require(
        "mpf-at-" + multipath_fabric::process_nonce() + "-" + std::to_string(++attempts));
    return context;
  }
};

[[nodiscard]] int report(const multipath_fabric::FabricOutcome& outcome) {
  return report(outcome, is_transport_failure(outcome.code));
}

[[nodiscard]] int run_path_command(const std::vector<std::string>& positional,
                                   CliSession& session) {
  if (positional_size(positional) < 3) {
    usage();
    return kExitUsage;
  }
  const std::string action = positional_at(positional, 1);
  if (action == "declare") {
    if (positional_size(positional) < 5) {
      usage();
      return kExitUsage;
    }
    const auto path = multipath_fabric::PathId::parse(positional_at(positional, 2));
    std::uint64_t generation_value = 0;
    const std::string generation_text = positional_at(positional, 3);
    for (const char c : generation_text) {
      if (c < '0' || c > '9') {
        generation_value = 0;
        break;
      }
      generation_value = generation_value * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    const auto state = multipath_fabric::parse_path_authority_state(positional_at(positional, 4));
    const auto generation =
        multipath_fabric::PathAuthorityGeneration::from_value(generation_value);
    if (!path.has_value() || !state.has_value() || !generation.has_value()) {
      std::cerr << "path declare requires PATH GENERATION STATE where STATE is one of "
                   "AUTHORIZED CONDITIONALLY_AUTHORIZED REVALIDATION_REQUIRED REJECTED REVOKED "
                   "STALE RETIRED\n";
      return kExitUsage;
    }
    multipath_fabric::PathAuthorityView view;
    view.path = *path;
    view.generation = *generation;
    view.state = *state;
    return report(session.client.declare_path_authority(session.next_context(), view));
  }
  if (action == "refresh") {
    const auto path = multipath_fabric::PathId::parse(positional_at(positional, 2));
    if (!path.has_value()) {
      std::cerr << "path refresh requires a valid PATH\n";
      return kExitUsage;
    }
    return report(session.client.refresh_path(session.next_context(), *path));
  }
  usage();
  return kExitUsage;
}

[[nodiscard]] int run_member_command(const std::vector<std::string>& positional,
                                     CliSession& session) {
  if (positional_size(positional) < 4) {
    usage();
    return kExitUsage;
  }
  const std::string action = positional_at(positional, 1);
  const auto set_id = multipath_fabric::MultipathSetId::parse(positional_at(positional, 2));
  if (!set_id.has_value()) {
    std::cerr << "invalid set identity\n";
    return kExitUsage;
  }
  if (action == "add") {
    if (positional_size(positional) < 5) {
      usage();
      return kExitUsage;
    }
    const auto path = multipath_fabric::PathId::parse(positional_at(positional, 3));
    std::uint64_t generation = 0;
    for (const char c : positional_at(positional, 4)) {
      if (c < '0' || c > '9') {
        generation = 0;
        break;
      }
      generation = generation * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    const auto generation_value = multipath_fabric::PathAuthorityGeneration::from_value(generation);
    if (!path.has_value() || !generation_value.has_value()) {
      std::cerr << "member add requires SETID PATH GENERATION with GENERATION >= 1\n";
      return kExitUsage;
    }
    return report(session.client.add_member(session.next_context(), *set_id, *path,
                                            *generation_value));
  }
  if (action == "add-bulk") {
    std::vector<multipath_fabric::MemberRequest> requests;
    for (std::size_t i = 3; i < positional_size(positional); ++i) {
      const std::string token = positional_at(positional, i);
      const std::size_t colon = token.find(':');
      if (colon == std::string::npos) {
        continue;
      }
      const auto path = multipath_fabric::PathId::parse(token.substr(0, colon));
      std::uint64_t generation = 0;
      for (std::size_t k = colon + 1; k < token.size(); ++k) {
        const char c = token[k];
        if (c < '0' || c > '9') {
          generation = 0;
          break;
        }
        generation = generation * 10ULL + static_cast<std::uint64_t>(c - '0');
      }
      const auto generation_value =
          multipath_fabric::PathAuthorityGeneration::from_value(generation);
      if (!path.has_value() || !generation_value.has_value()) {
        std::cerr << "add-bulk requires PATH:GENERATION entries\n";
        return kExitUsage;
      }
      multipath_fabric::MemberRequest request;
      request.path_id = *path;
      request.authority_generation = *generation_value;
      requests.push_back(std::move(request));
    }
    if (requests.empty()) {
      std::cerr << "add-bulk requires at least one PATH:GENERATION entry\n";
      return kExitUsage;
    }
    return report(session.client.add_members(session.next_context(), *set_id, requests));
  }
  const auto member_id = multipath_fabric::MultipathMemberId::parse(positional_at(positional, 3));
  if (!member_id.has_value()) {
    std::cerr << "invalid member identity\n";
    return kExitUsage;
  }
  if (action == "remove") {
    return report(session.client.remove_member(session.next_context(), *set_id, *member_id,
                                               "operator removal"));
  }
  if (action == "withdraw") {
    return report(session.client.withdraw_member(session.next_context(), *set_id, *member_id,
                                                 "operator withdrawal"));
  }
  if (action == "revalidate") {
    return report(session.client.revalidate_member(session.next_context(), *set_id, *member_id));
  }
  if (action == "replace") {
    if (positional_size(positional) < 6) {
      usage();
      return kExitUsage;
    }
    const auto path = multipath_fabric::PathId::parse(positional_at(positional, 4));
    std::uint64_t generation = 0;
    for (const char c : positional_at(positional, 5)) {
      if (c < '0' || c > '9') {
        generation = 0;
        break;
      }
      generation = generation * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    const auto generation_value = multipath_fabric::PathAuthorityGeneration::from_value(generation);
    if (!path.has_value() || !generation_value.has_value()) {
      std::cerr << "member replace requires SETID MEMBERID PATH GENERATION\n";
      return kExitUsage;
    }
    return report(session.client.replace_member(session.next_context(), *set_id, *member_id,
                                                *path, *generation_value,
                                                "operator replacement"));
  }
  if (action == "enable" || action == "disable") {
    return report(session.client.set_member_admin_enabled(session.next_context(), *set_id,
                                                          *member_id, action == "enable"));
  }
  usage();
  return kExitUsage;
}

[[nodiscard]] int run_set_command(const mpf_tool::Arguments& arguments,
                                  const std::vector<std::string>& positional,
                                  CliSession& session) {
  if (positional_size(positional) < 2) {
    usage();
    return kExitUsage;
  }
  const std::string action = positional_at(positional, 1);
  if (action == "create") {
    const auto name = multipath_fabric::MultipathSetName::parse(arguments.text("--name", ""));
    if (!name.has_value()) {
      std::cerr << "set create requires --name NAME\n";
      return kExitUsage;
    }
    multipath_fabric::SetKey key;
    key.fabric = session.scope.fabric;
    key.name_space = session.scope.name_space;
    key.name = *name;
    multipath_fabric::SetOptions options;
    options.minimum_usable_members = arguments.number("--minimum", 1);
    options.admin_enabled = !arguments.has("--admin-disabled");
    options.conditional_authority_permitted = arguments.has("--conditional");
    return report(session.client.create_set(session.next_context(), key, options));
  }
  if (action == "list") {
    std::vector<multipath_fabric::MultipathSetId> ids;
    const multipath_fabric::FabricOutcome outcome = session.client.list_sets(ids);
    const int code = report(outcome);
    for (const auto& id : ids) {
      std::cout << "set " << id.view() << '\n';
    }
    return code;
  }
  if (positional_size(positional) < 3) {
    usage();
    return kExitUsage;
  }
  const auto set_id = multipath_fabric::MultipathSetId::parse(positional_at(positional, 2));
  if (!set_id.has_value()) {
    std::cerr << "invalid set identity\n";
    return kExitUsage;
  }
  if (action == "show") {
    multipath_fabric::SetSnapshot snapshot;
    const multipath_fabric::FabricOutcome outcome = session.client.query_set(*set_id, snapshot);
    const int code = report(outcome);
    if (outcome.succeeded()) {
      std::cout << snapshot.render() << '\n';
    }
    return code;
  }
  if (action == "publish") {
    return report(session.client.publish_set(session.next_context(), *set_id));
  }
  if (action == "withdraw") {
    return report(session.client.withdraw_set(session.next_context(), *set_id,
                                              arguments.text("--reason", "operator withdrawal")));
  }
  if (action == "complete-withdrawal") {
    return report(session.client.complete_withdrawal(session.next_context(), *set_id));
  }
  if (action == "revalidate") {
    return report(session.client.revalidate_set(session.next_context(), *set_id));
  }
  if (action == "enable" || action == "disable") {
    return report(session.client.set_admin_enabled(session.next_context(), *set_id,
                                                   action == "enable"));
  }
  if (action == "minimum") {
    if (positional_size(positional) < 4) {
      usage();
      return kExitUsage;
    }
    std::uint64_t minimum = 0;
    for (const char c : positional_at(positional, 3)) {
      if (c < '0' || c > '9') {
        minimum = 0;
        break;
      }
      minimum = minimum * 10ULL + static_cast<std::uint64_t>(c - '0');
    }
    return report(session.client.set_minimum(session.next_context(), *set_id, minimum));
  }
  if (action == "policy") {
    if (positional_size(positional) < 4) {
      usage();
      return kExitUsage;
    }
    const std::string mode = positional_at(positional, 3);
    if (mode != "authorized" && mode != "conditional") {
      std::cerr << "set policy requires authorized|conditional\n";
      return kExitUsage;
    }
    return report(session.client.set_conditional_policy(session.next_context(), *set_id,
                                                        mode == "conditional"));
  }
  if (action == "revoke") {
    if (positional_size(positional) < 4) {
      usage();
      return kExitUsage;
    }
    const auto reason = multipath_fabric::parse_revocation_reason(positional_at(positional, 3));
    if (!reason.has_value()) {
      std::cerr << "revocation reason must be one of ADMINISTRATIVE SECURITY POLICY_VIOLATION "
                   "AUTHORITY_REVOKED OPERATOR_REQUEST\n";
      return kExitUsage;
    }
    return report(session.client.revoke_set(session.next_context(), *set_id, *reason,
                                            arguments.text("--detail", "")));
  }
  if (action == "retire") {
    return report(session.client.retire_set(session.next_context(), *set_id,
                                            arguments.text("--reason", "operator")));
  }
  if (action == "supersede") {
    if (positional_size(positional) < 4) {
      usage();
      return kExitUsage;
    }
    const auto successor =
        multipath_fabric::MultipathSetId::parse(positional_at(positional, 3));
    if (!successor.has_value()) {
      std::cerr << "invalid successor set identity\n";
      return kExitUsage;
    }
    return report(session.client.supersede_set(session.next_context(), *set_id, *successor));
  }
  usage();
  return kExitUsage;
}

int main(int argc, char** argv) {
  mpf_tool::Arguments arguments(argc, argv);
  const std::vector<std::string> positional = arguments.positionals();
  if (positional_size(positional) == 0 || arguments.has("--help")) {
    usage();
    return arguments.has("--help") ? kExitOk : kExitUsage;
  }
  const std::string command = positional_at(positional, 0);
  if (command == "version") {
    std::cout << multipath_fabric::product_name << ' ' << multipath_fabric::version_string
              << " persistence_format=" << multipath_fabric::persistence_format_version
              << " wire_protocol=" << multipath_fabric::wire_protocol_version << '\n';
    return kExitOk;
  }
  if (command == "limits") {
    const multipath_fabric::Limits limits;
    for (const auto& entry : limits.describe()) {
      std::cout << entry.first << '=' << entry.second << '\n';
    }
    return kExitOk;
  }
  if (command == "store") {
    if (positional_size(positional) < 3 || positional_at(positional, 1) != "inspect") {
      usage();
      return kExitUsage;
    }
    multipath_fabric::StoreStatistics statistics;
    const multipath_fabric::FabricOutcome outcome =
        multipath_fabric::FabricEngine::inspect_store_file(positional_at(positional, 2),
                                                           statistics);
    mpf_tool::print_outcome(outcome);
    if (outcome.succeeded()) {
      std::cout << statistics.render() << '\n';
      return kExitOk;
    }
    return kExitRejected;
  }

  const std::string host = arguments.text("--host", "127.0.0.1");
  const std::uint64_t port = arguments.number("--port", 0);
  if (port == 0 || port > 65535) {
    std::cerr << "mpf requires --port N for coordinator commands\n";
    return kExitUsage;
  }

  CliSession session;
  const multipath_fabric::FabricOutcome connected = session.client.connect(
      host, static_cast<std::uint16_t>(port));
  if (!connected.succeeded()) {
    mpf_tool::print_outcome(connected);
    return kExitTransport;
  }

  const auto publisher =
      multipath_fabric::PublisherId::parse(arguments.text("--publisher", "mpf-cli"));
  const auto boot = multipath_fabric::WorkerBootId::parse(
      arguments.text("--boot", "mpf-cli-" + multipath_fabric::process_nonce()));
  const auto fabric = multipath_fabric::FabricId::parse(arguments.text("--fabric", "fabric-main"));
  const auto name_space =
      multipath_fabric::MultipathNamespace::parse(arguments.text("--namespace", "mp-ns"));
  if (!publisher.has_value() || !boot.has_value() || !fabric.has_value() ||
      !name_space.has_value()) {
    std::cerr << "publisher, boot, fabric and namespace must be valid identities\n";
    return kExitUsage;
  }
  session.publisher = *publisher;
  session.boot = *boot;
  session.scope.fabric = *fabric;
  session.scope.name_space = *name_space;

  const multipath_fabric::FabricOutcome registered =
      session.client.register_publisher(session.publisher, session.boot, session.scope);
  if (!registered.succeeded()) {
    mpf_tool::print_outcome(registered);
    return kExitRejected;
  }

  if (command == "authority") {
    // Rendered from the coordinator's own epoch and the local session; the full
    // authority description is available in process through FabricEngine.
    std::cout << "epoch=" << session.client.governing_epoch().value() << " session="
              << session.client.session().view() << " publisher=" << publisher->view()
              << " boot=" << boot->view() << " scope=" << session.scope.render() << '\n';
    return kExitOk;
  }
  if (command == "epoch") {
    if (positional_size(positional) < 2 || positional_at(positional, 1) != "advance") {
      usage();
      return kExitUsage;
    }
    const multipath_fabric::FabricOutcome outcome =
        session.client.advance_epoch(session.next_context(), session.client.governing_epoch());
    const int code = report(outcome);
    if (code == kExitOk) {
      const multipath_fabric::FabricOutcome refreshed = session.client.refresh_epoch();
      if (refreshed.succeeded()) {
        std::cout << "governing_epoch=" << session.client.governing_epoch().value() << '\n';
      }
    }
    return code;
  }
  if (command == "path") {
    return run_path_command(positional, session);
  }
  if (command == "set") {
    return run_set_command(arguments, positional, session);
  }
  if (command == "member") {
    return run_member_command(positional, session);
  }
  if (command == "snapshot") {
    if (positional_size(positional) < 2) {
      usage();
      return kExitUsage;
    }
    const auto set_id = multipath_fabric::MultipathSetId::parse(positional_at(positional, 1));
    if (!set_id.has_value()) {
      std::cerr << "invalid set identity\n";
      return kExitUsage;
    }
    multipath_fabric::SetSnapshot snapshot;
    multipath_fabric::FabricOutcome outcome = multipath_fabric::make_outcome(
        multipath_fabric::OutcomeCode::OK, std::string());
    if (positional_size(positional) >= 3) {
      const auto snapshot_id = multipath_fabric::SnapshotId::parse(positional_at(positional, 2));
      if (!snapshot_id.has_value()) {
        std::cerr << "invalid snapshot identity\n";
        return kExitUsage;
      }
      outcome = session.client.request_snapshot(*set_id, *snapshot_id, snapshot);
    } else {
      outcome = session.client.query_set(*set_id, snapshot);
    }
    const int code = report(outcome);
    if (outcome.succeeded()) {
      std::cout << snapshot.render() << '\n';
      std::cout << "digest " << snapshot.digest.to_hex() << '\n';
    }
    return code;
  }
  if (command == "diff") {
    if (positional_size(positional) < 2) {
      usage();
      return kExitUsage;
    }
    const auto set_id = multipath_fabric::MultipathSetId::parse(positional_at(positional, 1));
    if (!set_id.has_value()) {
      std::cerr << "invalid set identity\n";
      return kExitUsage;
    }
    multipath_fabric::SetSnapshot current;
    const multipath_fabric::FabricOutcome outcome = session.client.query_set(*set_id, current);
    if (!outcome.succeeded()) {
      return report(outcome);
    }
    std::cout << "set " << set_id->view() << " snapshot=" << current.snapshot_id.view()
              << " generation=" << current.generation.value() << '\n';
    for (const auto& entry : current.history) {
      std::cout << "history " << entry.render() << '\n';
    }
    return kExitOk;
  }
  if (command == "explain") {
    if (positional_size(positional) < 2) {
      usage();
      return kExitUsage;
    }
    const auto set_id = multipath_fabric::MultipathSetId::parse(positional_at(positional, 1));
    if (!set_id.has_value()) {
      std::cerr << "invalid set identity\n";
      return kExitUsage;
    }
    multipath_fabric::SetExplanation explanation;
    const multipath_fabric::FabricOutcome outcome =
        session.client.explain_set(*set_id, explanation);
    const int code = report(outcome);
    if (outcome.succeeded()) {
      std::cout << explanation.render() << '\n';
    }
    return code;
  }

  usage();
  return kExitUsage;
}
