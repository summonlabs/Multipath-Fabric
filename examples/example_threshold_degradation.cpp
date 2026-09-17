// Example: threshold semantics as members become unusable.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-3", "fabric-a", "ns-a");
  expect(publisher.registered(), "publisher registration");

  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("threshold-demo");
  SetOptions options;
  options.minimum_usable_members = 2;
  const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;
  expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");
  for (int index = 0; index < 4; ++index) {
    const std::string path = "path-threshold-" + std::to_string(index);
    expect(publisher.declare(path, 1).succeeded(), "declare");
    expect(engine
               .add_member(publisher.context(), set_id, PathId::require(path),
                           PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member");
  }

  const auto report = [&](const std::string& label) {
    const auto snapshot = engine.snapshot(set_id);
    line(label + ": lifecycle=" + std::string(to_string(snapshot->lifecycle)) +
         " usable=" + std::to_string(snapshot->usable_member_count) + "/" +
         std::to_string(snapshot->member_count) +
         " minimum=" + std::to_string(snapshot->minimum_usable_members) +
         " readiness=" + std::string(to_string(snapshot->readiness)));
    return snapshot->lifecycle;
  };

  expect(report("all four usable") == SetLifecycle::ACTIVE, "4/4 is ACTIVE");
  expect(publisher.declare("path-threshold-0", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject one path");
  expect(report("three usable") == SetLifecycle::ACTIVE, "3/4 is ACTIVE");
  expect(publisher.declare("path-threshold-1", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject a second path");
  expect(report("two usable") == SetLifecycle::ACTIVE, "2/4 is exactly at the requirement");
  expect(publisher.declare("path-threshold-2", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject a third path");
  expect(report("one usable") == SetLifecycle::DEGRADED, "1/4 is DEGRADED");
  expect(publisher.declare("path-threshold-3", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject the last path");
  expect(report("none usable") == SetLifecycle::EXHAUSTED, "0/4 is EXHAUSTED");

  // Multipath Fabric does not search for replacement paths. It reports the state
  // precisely; selecting new candidates is Path Planner's job.
  const auto explanation = engine.explain_set(set_id);
  expect(explanation.has_value(), "explanation available");
  line(explanation->render());
  return finish("example_threshold_degradation");
}
