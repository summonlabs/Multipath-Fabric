// Example: coordinator restart, epoch advance and conservative recovery.
#include <filesystem>

#include "example_support.hpp"
#include "multipath_fabric/multipath_fabric.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  const std::filesystem::path store =
      std::filesystem::temp_directory_path() / ("mpf-example-restart-" + process_nonce() + ".bin");
  const std::string store_path = store.string();
  std::error_code error;
  std::filesystem::remove(store_path, error);
  std::filesystem::remove(store_path + ".bak", error);

  {
    FabricEngine engine;
    Publisher publisher(engine, "example-publisher", "example-boot-6a", "fabric-a", "ns-a");
    expect(publisher.registered(), "register");
    SetKey key;
    key.fabric = publisher.scope().fabric;
    key.name_space = publisher.scope().name_space;
    key.name = MultipathSetName::require("restart-demo");
    SetOptions options;
    options.minimum_usable_members = 1;
    const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;
    expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");
    expect(publisher.declare("path-restart-0", 1).succeeded(), "declare");
    expect(engine
               .add_member(publisher.context(), set_id, PathId::require("path-restart-0"),
                           PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member");
    expect(engine.save_store(store_path).succeeded(), "save store");
    expect(engine.snapshot(set_id)->readiness == RouteReadiness::READY, "ready before restart");
  }

  // The coordinator restarts from the same durable store.
  FabricEngine restarted;
  const FabricOutcome loaded = restarted.load_store(store_path);
  expect(loaded.succeeded(), "load store");
  expect(restarted.epoch().value() == 2, "epoch advanced on restart");
  expect(restarted.describe_authority().registrations.empty(),
         "no publisher authority is restored from disk");

  std::vector<MultipathSetId> listed = restarted.list_sets();
  expect(listed.size() == 1, "one set recovered");
  const MultipathSetId recovered = listed.front();
  expect(restarted.snapshot(recovered)->readiness == RouteReadiness::REVALIDATION_REQUIRED,
         "recovered set is conservatively not ready");
  expect(restarted.snapshot(recovered)->member_count == 1, "durable membership survived");

  // Path Authority views are consumed, not owned: the coordinator does not
  // persist them, so the Path Authority bridge re-declares the current views
  // before revalidation can succeed.
  Publisher fresh(restarted, "example-publisher", "example-boot-6b", "fabric-a", "ns-a");
  expect(fresh.registered(), "fresh registration");
  expect(fresh.declare("path-restart-0", 1).succeeded(), "re-declare the Path Authority view");
  expect(restarted.revalidate_set(fresh.context(), recovered).succeeded(), "revalidate");
  expect(restarted.snapshot(recovered)->readiness == RouteReadiness::READY, "ready again");

  std::filesystem::remove(store_path, error);
  std::filesystem::remove(store_path + ".bak", error);
  return finish("example_coordinator_restart");
}
