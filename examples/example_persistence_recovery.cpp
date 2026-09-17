// Example: persistence encoding, inspection and corruption rejection.
#include <filesystem>
#include <fstream>

#include "example_support.hpp"

int main() {
  using namespace multipath_fabric;
  using namespace mpf_example;

  const std::filesystem::path base =
      std::filesystem::temp_directory_path() / ("mpf-example-persistence-" + process_nonce());
  std::error_code error;
  std::filesystem::create_directories(base, error);
  const std::string store_path = (base / "store.bin").string();

  FabricEngine engine;
  Publisher publisher(engine, "example-publisher", "example-boot-7", "fabric-a", "ns-a");
  expect(publisher.registered(), "register");
  SetKey key;
  key.fabric = publisher.scope().fabric;
  key.name_space = publisher.scope().name_space;
  key.name = MultipathSetName::require("persistence-demo");
  SetOptions options;
  options.minimum_usable_members = 2;
  const MultipathSetId set_id = *engine.create_set(publisher.context(), key, options).set_id;
  expect(engine.publish_set(publisher.context(), set_id).succeeded(), "publish");
  for (int index = 0; index < 3; ++index) {
    const std::string path = "path-persistence-" + std::to_string(index);
    expect(publisher.declare(path, 1).succeeded(), "declare");
    expect(engine
               .add_member(publisher.context(), set_id, PathId::require(path),
                           PathAuthorityGeneration::require(1))
               .succeeded(),
           "add member");
  }
  expect(engine.save_store(store_path).succeeded(), "save store");

  StoreStatistics statistics;
  expect(FabricEngine::inspect_store_file(store_path, statistics).succeeded(), "inspect store");
  line(statistics.render());
  expect(statistics.set_count == 1, "one set persisted");
  expect(statistics.member_count == 3, "three members persisted");

  // A corrupt store is refused rather than partially applied.
  std::ifstream input(store_path, std::ios::binary);
  std::vector<char> bytes((std::istreambuf_iterator<char>(input)),
                          std::istreambuf_iterator<char>());
  input.close();
  expect(bytes.size() > 40, "store has content");
  bytes[bytes.size() - 12] = static_cast<char>(bytes[bytes.size() - 12] ^ 0x5A);
  const std::string corrupt_path = (base / "corrupt.bin").string();
  {
    std::ofstream output(corrupt_path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  FabricEngine recovered;
  const FabricOutcome rejected = recovered.load_store(corrupt_path);
  expect(!rejected.succeeded(), "corrupt store is rejected");
  expect(rejected.code == OutcomeCode::INTEGRITY_ERROR ||
             rejected.code == OutcomeCode::STORE_CORRUPT,
         "rejection is an integrity failure");
  line("rejected corrupt store: " + rejected.render());

  std::filesystem::remove_all(base, error);
  return finish("example_persistence_recovery");
}
