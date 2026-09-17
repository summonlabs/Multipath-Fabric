// Example: create, publish and inspect a basic multipath set.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-1", "fabric-a", "ns-a");
  expect(publisher.registered(), "publisher registration");

  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("edge-transit");

  SetOptions options;
  options.minimum_usable_members = 2;
  const FabricOutcome created = engine.create_set(publisher.context(), key, options);
  expect(created.succeeded(), "create_set succeeds");
  expect(created.code == OutcomeCode::CREATED, "create_set returns CREATED");
  const MultipathSetId set_id = *created.set_id;
  line("created " + set_id.str() + " generation " + std::to_string(created.set_generation->value()));

  const FabricOutcome published = engine.publish_set(publisher.context(), set_id);
  expect(published.succeeded(), "publish_set succeeds");

  for (int index = 0; index < 3; ++index) {
    const std::string path = "path-basic-" + std::to_string(index);
    expect(publisher.declare(path, 1).succeeded(), "declare path " + path);
    expect(engine.add_member(publisher.context(), set_id, PathId::require(path),
                             PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member " + path);
  }

  const auto snapshot = engine.snapshot(set_id);
  expect(snapshot.has_value(), "snapshot available");
  if (snapshot.has_value()) {
    line(snapshot->render());
    expect(snapshot->lifecycle == SetLifecycle::ACTIVE, "set is ACTIVE");
    expect(snapshot->readiness == RouteReadiness::READY, "set is ready for Route Fabric");
    expect(snapshot->usable_member_count == 3, "three usable members");
  }
  return finish("example_basic_set");
}
