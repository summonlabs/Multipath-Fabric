// Independent downstream consumer.
//
// Uses the installed package surface only: create a synthetic set, add two
// exact path members, query the set state, invalidate one member, observe the
// exact resulting state and exit successfully.
#include <cstdio>
#include <string>

#include <multipath_fabric/multipath_fabric.hpp>

namespace {

int g_failures = 0;

void expect(bool condition, const char* description) {
  if (!condition) {
    ++g_failures;
    std::printf("EXPECTATION FAILED: %s\n", description);
  }
}

}  // namespace

int main() {
  using namespace multipath_fabric;

  std::printf("MultipathFabric %.*s consumer\n",
              static_cast<int>(version_string.size()), version_string.data());

  FabricEngine engine;
  const PublisherId publisher = PublisherId::require("consumer-publisher");
  const WorkerBootId boot = WorkerBootId::require("consumer-boot");
  const SessionId session = SessionId::require("consumer-session");
  AuthorityScope scope;
  scope.fabric = FabricId::require("consumer-fabric");
  scope.name_space = MultipathNamespace::require("consumer-ns");
  expect(engine.register_publisher(publisher, boot, scope, session).succeeded(),
         "register publisher");

  std::uint64_t attempts = 0;
  const auto context = [&]() {
    MutationContext value;
    value.epoch = engine.epoch();
    value.publisher = publisher;
    value.worker_boot = boot;
    value.session = session;
    value.attempt =
        MutationAttemptId::require("consumer-attempt-" + std::to_string(++attempts));
    return value;
  };

  SetKey key;
  key.fabric = scope.fabric;
  key.name_space = scope.name_space;
  key.name = MultipathSetName::require("consumer-set");
  SetOptions options;
  options.minimum_usable_members = 1;
  const FabricOutcome created = engine.create_set(context(), key, options);
  expect(created.succeeded(), "create set");
  expect(engine.publish_set(context(), created.set_id.value()).succeeded(), "publish set");
  const MultipathSetId set_id = *created.set_id;

  for (int index = 0; index < 2; ++index) {
    const std::string path = "consumer-path-" + std::to_string(index);
    PathAuthorityView view;
    view.path = PathId::require(path);
    view.generation = PathAuthorityGeneration::require(1);
    view.state = PathAuthorityState::AUTHORIZED;
    expect(engine.declare_path_authority(context(), view).succeeded(), "declare path");
    expect(engine
               .add_member(context(), set_id, view.path, view.generation)
               .succeeded(),
           "add member");
  }

  const auto before = engine.snapshot(set_id);
  expect(before.has_value(), "query set state");
  if (before.has_value()) {
    std::printf("before: lifecycle=%s usable=%llu readiness=%s\n",
                std::string(to_string(before->lifecycle)).c_str(),
                static_cast<unsigned long long>(before->usable_member_count),
                std::string(to_string(before->readiness)).c_str());
    expect(before->lifecycle == SetLifecycle::ACTIVE, "set is ACTIVE");
    expect(before->usable_member_count == 2, "two usable members");
    expect(before->readiness == RouteReadiness::READY, "set is ready");
  }

  // Invalidate one exact path through Path Authority.
  PathAuthorityView rejected;
  rejected.path = PathId::require("consumer-path-0");
  rejected.generation = PathAuthorityGeneration::require(1);
  rejected.state = PathAuthorityState::REJECTED;
  expect(engine.declare_path_authority(context(), rejected).succeeded(), "invalidate path");

  const auto after = engine.snapshot(set_id);
  expect(after.has_value(), "query set state after invalidation");
  if (after.has_value()) {
    std::printf("after:  lifecycle=%s usable=%llu readiness=%s\n",
                std::string(to_string(after->lifecycle)).c_str(),
                static_cast<unsigned long long>(after->usable_member_count),
                std::string(to_string(after->readiness)).c_str());
    expect(after->usable_member_count == 1, "one usable member remains");
    expect(after->lifecycle == SetLifecycle::ACTIVE, "minimum requirement still satisfied");
    const MemberSnapshot* member = after->find_member(PathId::require("consumer-path-0"));
    expect(member != nullptr && !member->usable, "invalidated member is not usable");
    expect(member != nullptr && member->currentness == MemberCurrentness::PATH_REJECTED,
           "invalidation cause is preserved");
  }

  // Invalidate the second path: the set drops below its minimum requirement.
  PathAuthorityView second;
  second.path = PathId::require("consumer-path-1");
  second.generation = PathAuthorityGeneration::require(1);
  second.state = PathAuthorityState::REJECTED;
  expect(engine.declare_path_authority(context(), second).succeeded(), "invalidate second path");
  const auto final_state = engine.snapshot(set_id);
  expect(final_state.has_value(), "query final state");
  if (final_state.has_value()) {
    std::printf("final:  lifecycle=%s usable=%llu readiness=%s\n",
                std::string(to_string(final_state->lifecycle)).c_str(),
                static_cast<unsigned long long>(final_state->usable_member_count),
                std::string(to_string(final_state->readiness)).c_str());
    expect(final_state->lifecycle == SetLifecycle::EXHAUSTED, "set is EXHAUSTED");
    expect(final_state->readiness == RouteReadiness::INSUFFICIENT_MEMBERS,
           "readiness reports insufficient members");
  }

  if (g_failures == 0) {
    std::printf("consumer OK\n");
    return 0;
  }
  std::printf("consumer FAILED %d expectation(s)\n", g_failures);
  return 1;
}
