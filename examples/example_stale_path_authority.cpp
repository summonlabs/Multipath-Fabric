// Example: a stale Path Authority generation stops counting as usable.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-4", "fabric-a", "ns-a");
  expect(publisher.registered(), "publisher registration");

  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("authority-demo");
  SetOptions options;
  options.minimum_usable_members = 1;
  const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;
  expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");

  // The member is admitted against exact Path Authority generation 7.
  expect(publisher.declare("path-authority-0", 7).succeeded(), "declare generation 7");
  expect(engine
             .add_member(publisher.context(), set_id, PathId::require("path-authority-0"),
                         PathAuthorityGeneration::require(7))
             .succeeded(),
         "admit at generation 7");
  auto snapshot = engine.snapshot(set_id);
  expect(snapshot->usable_member_count == 1, "member is usable at generation 7");
  const MultipathMemberId member_id = snapshot->members.front().id;

  // Path Authority advances to generation 8. The historical authorization for
  // generation 7 must not keep counting.
  expect(publisher.declare("path-authority-0", 8, PathAuthorityState::AUTHORIZED).succeeded(),
         "declare generation 8");
  snapshot = engine.snapshot(set_id);
  expect(snapshot->usable_member_count == 0, "stale generation is not usable");
  expect(snapshot->find_member(member_id)->currentness ==
             MemberCurrentness::STALE_PATH_AUTHORITY,
         "cause is preserved as STALE_PATH_AUTHORITY");
  line(snapshot->render());

  // An explicit member revalidation rebinds the member and restores usability.
  const FabricOutcome revalidated =
      engine.revalidate_member(publisher.context(), set_id, member_id);
  expect(revalidated.succeeded(), "member revalidation completes");
  expect(revalidated.code == OutcomeCode::MEMBER_REVALIDATED, "member became usable");
  snapshot = engine.snapshot(set_id);
  expect(snapshot->find_member(member_id)->bound_authority_generation.value() == 8,
         "rebound to generation 8");
  expect(snapshot->usable_member_count == 1, "member is usable again");
  return finish("example_stale_path_authority");
}
