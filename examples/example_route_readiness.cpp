// Example: the Route Fabric consumption surface.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-8", "fabric-a", "ns-a");
  expect(publisher.registered(), "register");
  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("route-readiness-demo");
  SetOptions options;
  options.minimum_usable_members = 2;
  const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;

  // Route Fabric never has to infer readiness from low-level fields.
  const auto readiness = [&]() {
    const auto value = engine.readiness(set_id);
    return value.has_value() ? *value : RouteReadiness::RETIRED;
  };
  expect(readiness() == RouteReadiness::NOT_PUBLISHED, "declared set is not published");
  expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");
  expect(readiness() == RouteReadiness::INSUFFICIENT_MEMBERS, "no members yet");

  for (int index = 0; index < 2; ++index) {
    const std::string path = "path-readiness-" + std::to_string(index);
    expect(publisher.declare(path, 1).succeeded(), "declare");
    expect(engine
               .add_member(publisher.context(), set_id, PathId::require(path),
                           PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member");
  }
  expect(readiness() == RouteReadiness::READY, "two usable members is READY");

  // A ready set means only that these exact paths are currently governed members
  // eligible for simultaneous use. It says nothing about distribution, hashing,
  // weighting, diversity, congestion or reservation.
  expect(publisher.declare("path-readiness-0", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject one path");
  expect(readiness() == RouteReadiness::DEGRADED_BUT_READY, "one usable member stays ready");
  expect(publisher.declare("path-readiness-1", 1, PathAuthorityState::REJECTED).succeeded(),
         "reject the other path");
  expect(readiness() == RouteReadiness::INSUFFICIENT_MEMBERS, "no usable members");

  expect(engine.set_admin_enabled(publisher.context(), set_id, false).succeeded(),
         "administratively disable");
  expect(readiness() == RouteReadiness::ADMIN_DISABLED, "administration is a distinct fact");
  expect(engine.set_admin_enabled(publisher.context(), set_id, true).succeeded(), "re-enable");
  expect(engine.retire_set(publisher.context(), set_id, "end of life").succeeded(), "retire");
  expect(readiness() == RouteReadiness::RETIRED, "retired sets are never ready");
  return finish("example_route_readiness");
}
