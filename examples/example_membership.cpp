// Example: adding, withdrawing, removing and replacing members.
#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-2", "fabric-a", "ns-a");
  expect(publisher.registered(), "publisher registration");

  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("membership-demo");
  SetOptions options;
  options.minimum_usable_members = 1;
  const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;
  expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");

  for (int index = 0; index < 3; ++index) {
    const std::string path = "path-membership-" + std::to_string(index);
    expect(publisher.declare(path, 1).succeeded(), "declare");
    expect(engine
               .add_member(publisher.context(), set_id, PathId::require(path),
                           PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member");
  }
  auto snapshot = engine.snapshot(set_id);
  expect(snapshot.has_value(), "snapshot");
  const MultipathMemberId second = snapshot->members[1].id;

  // Withdrawal keeps the record and marks the relation terminal.
  expect(engine.withdraw_member(publisher.context(), set_id, second, "drained").succeeded(),
         "withdraw member");
  snapshot = engine.snapshot(set_id);
  expect(snapshot->find_member(second)->lifecycle == MemberLifecycle::WITHDRAWN,
         "withdrawn member lifecycle");

  // Removal deletes the relation entirely and frees the path for readmission.
  const MultipathMemberId third = snapshot->members[2].id;
  expect(engine.remove_member(publisher.context(), set_id, third, "decommissioned").succeeded(),
         "remove member");
  snapshot = engine.snapshot(set_id);
  expect(snapshot->find_member(third) == nullptr, "removed member is gone");
  expect(engine
             .add_member(publisher.context(), set_id, PathId::require("path-membership-2"),
                         PathAuthorityGeneration::require(1))
             .succeeded(),
         "readmit the same path");

  // Replacement keeps full lineage between the old and the new relation.
  snapshot = engine.snapshot(set_id);
  const MultipathMemberId target = snapshot->members.front().id;
  expect(publisher.declare("path-membership-replacement", 1).succeeded(), "declare successor");
  const FabricOutcome replaced = engine.replace_member(
      publisher.context(), set_id, target, PathId::require("path-membership-replacement"),
      PathAuthorityGeneration::require(1), "optics moved");
  expect(replaced.succeeded(), "replace member");
  snapshot = engine.snapshot(set_id);
  const MemberSnapshot* old_member = snapshot->find_member(target);
  expect(old_member != nullptr, "predecessor is still recorded");
  if (old_member != nullptr) {
    expect(old_member->lifecycle == MemberLifecycle::SUPERSEDED, "predecessor is superseded");
    expect(old_member->successor.has_value(), "predecessor records its successor");
  }
  line(snapshot->render());
  return finish("example_membership");
}
