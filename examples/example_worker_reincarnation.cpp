// Example: worker reincarnation, fencing and re-establishing currentness.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher first(engine, "example-publisher", "example-boot-5a", "fabric-a", "ns-a");
  expect(first.registered(), "first incarnation registers");

  SetKey key;
  key.fabric = first.scope().fabric;
  key.name_space = first.scope().name_space;
  key.name = MultipathSetName::require("reincarnation-demo");
  SetOptions options;
  options.minimum_usable_members = 1;
  const MultipathSetId set_id = *engine.create_set(first.context(), key, options).set_id;
  expect(engine.publish_set(first.context(), set_id).succeeded(), "publish");
  expect(first.declare("path-reincarnation-0", 1).succeeded(), "declare");
  expect(engine
             .add_member(first.context(), set_id, PathId::require("path-reincarnation-0"),
                         PathAuthorityGeneration::require(1))
             .succeeded(),
         "add member");
  expect(engine.snapshot(set_id)->readiness == RouteReadiness::READY, "set is ready");

  // The worker dies. The coordinator fences the exact boot incarnation.
  const FabricOutcome fenced = engine.fence_worker(first.id(), first.boot(), "SESSION_LOST");
  expect(fenced.succeeded(), "fence succeeds");
  expect(engine.is_fenced(first.id(), first.boot()), "boot is fenced");
  expect(engine.snapshot(set_id)->currentness == SetCurrentness::REVALIDATION_REQUIRED,
         "live currentness must be re-established");
  expect(engine.snapshot(set_id)->member_count == 1, "durable membership survives");

  // The fenced incarnation can never mutate again, even with a fresh attempt id.
  MutationContext stale = first.context();
  expect(!engine.add_member(stale, set_id, PathId::require("path-reincarnation-0"),
                            PathAuthorityGeneration::require(1))
              .succeeded(),
         "fenced boot cannot mutate");
  expect(engine.add_member(stale, set_id, PathId::require("path-reincarnation-0"),
                           PathAuthorityGeneration::require(1))
             .code == OutcomeCode::STALE_WORKER,
         "rejection is STALE_WORKER");

  // A fresh incarnation registers and re-establishes live currentness.
  Publisher second(engine, "example-publisher", "example-boot-5b", "fabric-a", "ns-a", "2");
  expect(second.registered(), "second incarnation registers");
  const FabricOutcome revalidated = engine.revalidate_set(second.context(), set_id);
  expect(revalidated.succeeded(), "revalidation completes");
  expect(engine.snapshot(set_id)->readiness == RouteReadiness::READY, "set is ready again");
  expect(engine.snapshot(set_id)->currentness == SetCurrentness::CURRENT, "currentness restored");
  return finish("example_worker_reincarnation");
}
