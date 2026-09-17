cmake_minimum_required(VERSION 3.20)

project(MultipathFabric
        VERSION 1.0.0
        DESCRIPTION "Multipath Fabric -- simultaneous-path-set governance runtime"
        HOMEPAGE_URL "https://github.com/summonlabs/Multipath-Fabric"
        LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

option(MPF_BUILD_TESTS "Build the Multipath Fabric test suite" ON)
option(MPF_BUILD_TOOLS "Build the Multipath Fabric CLI and process tools" ON)
option(MPF_BUILD_EXAMPLES "Build the Multipath Fabric examples" ON)
option(MPF_BUILD_BENCHMARKS "Build the Multipath Fabric benchmarks" ON)
option(MPF_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(MPF_ENABLE_ANALYZE "Enable MSVC static analysis (/analyze)" OFF)
option(MPF_ENABLE_ASAN "Enable AddressSanitizer where the toolchain supports it" OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  if(MPF_WARNINGS_AS_ERRORS)
    add_compile_options(/WX)
  endif()
  if(MPF_ENABLE_ANALYZE)
    add_compile_options(/analyze)
  endif()
  if(MPF_ENABLE_ASAN)
    # Genuine MSVC AddressSanitizer. The runtime DLL is copied next to the
    # executables after the build by the asan-runtime target below.
    add_compile_options(/fsanitize=address)
    add_link_options(/fsanitize=address)
  endif()
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
  if(MPF_WARNINGS_AS_ERRORS)
    add_compile_options(-Werror)
  endif()
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------

set(MPF_LIBRARY_SOURCES
  src/authority.cpp
  src/detail/bytes.cpp
  src/detail/records.cpp
  src/diff.cpp
  src/explanation.cpp
  src/fabric_authority.cpp
  src/fabric_commit.cpp
  src/fabric_engine.cpp
  src/fabric_membership.cpp
  src/fabric_mutation.cpp
  src/fabric_query.cpp
  src/fabric_revalidation.cpp
  src/ids.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/outcome.cpp
  src/path_authority.cpp
  src/persistence.cpp
  src/client.cpp
  src/server.cpp
  src/socket.cpp
  src/wire.cpp
)

set(MPF_LIBRARY_HEADERS
  include/multipath_fabric/authority.hpp
  include/multipath_fabric/detail/bytes.hpp
  include/multipath_fabric/detail/checked.hpp
  include/multipath_fabric/detail/records.hpp
  include/multipath_fabric/diff.hpp
  include/multipath_fabric/explanation.hpp
  include/multipath_fabric/fabric.hpp
  include/multipath_fabric/ids.hpp
  include/multipath_fabric/lifecycle.hpp
  include/multipath_fabric/limits.hpp
  include/multipath_fabric/multipath_fabric.hpp
  include/multipath_fabric/outcome.hpp
  include/multipath_fabric/path_authority.hpp
  include/multipath_fabric/persistence.hpp
  include/multipath_fabric/snapshot.hpp
  include/multipath_fabric/version.hpp
  include/multipath_fabric/client.hpp
  include/multipath_fabric/server.hpp
  include/multipath_fabric/socket.hpp
  include/multipath_fabric/wire.hpp
)

add_library(MultipathFabric ${MPF_LIBRARY_SOURCES} ${MPF_LIBRARY_HEADERS})
add_library(SummonSoftwareLabs::MultipathFabric ALIAS MultipathFabric)

target_include_directories(MultipathFabric
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_compile_features(MultipathFabric PUBLIC cxx_std_20)
set_target_properties(MultipathFabric PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME MultipathFabric
)

find_package(Threads REQUIRED)
target_link_libraries(MultipathFabric PUBLIC Threads::Threads)

if(WIN32)
  # Winsock is used by the coordinator transport and by the acceptance-proving
  # distributed tests. It stays on the public link interface because the
  # installed socket/server/client headers are part of the package surface.
  target_link_libraries(MultipathFabric PUBLIC ws2_32)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------

install(TARGETS MultipathFabric
  EXPORT MultipathFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT MultipathFabricTargets
  FILE MultipathFabricTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MultipathFabric
)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/MultipathFabricConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/MultipathFabricConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MultipathFabric
)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/MultipathFabricConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/MultipathFabricConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/MultipathFabricConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/MultipathFabric
)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

if(MPF_BUILD_TOOLS)
  add_executable(mpf tools/mpf.cpp)
  target_link_libraries(mpf PRIVATE SummonSoftwareLabs::MultipathFabric)
  target_include_directories(mpf PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  add_executable(mpf_coordinator tools/mpf_coordinator.cpp)
  target_link_libraries(mpf_coordinator PRIVATE SummonSoftwareLabs::MultipathFabric)
  target_include_directories(mpf_coordinator PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  add_executable(mpf_publisher tools/mpf_publisher.cpp)
  target_link_libraries(mpf_publisher PRIVATE SummonSoftwareLabs::MultipathFabric)
  target_include_directories(mpf_publisher PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tools")

  install(TARGETS mpf mpf_coordinator mpf_publisher
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

if(MPF_BUILD_EXAMPLES)
  set(MPF_EXAMPLES
    example_basic_set
    example_membership
    example_threshold_degradation
    example_stale_path_authority
    example_worker_reincarnation
    example_coordinator_restart
    example_persistence_recovery
    example_route_readiness
  )
  foreach(example_name ${MPF_EXAMPLES})
    add_executable(${example_name} examples/${example_name}.cpp)
    target_link_libraries(${example_name} PRIVATE SummonSoftwareLabs::MultipathFabric)
    target_include_directories(${example_name}
      PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/examples")
  endforeach()
endif()

# ---------------------------------------------------------------------------
# Benchmarks
# ---------------------------------------------------------------------------

if(MPF_BUILD_BENCHMARKS)
  add_executable(mpf_benchmarks benchmarks/benchmark_main.cpp)
  target_link_libraries(mpf_benchmarks PRIVATE SummonSoftwareLabs::MultipathFabric)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(MPF_BUILD_TESTS)
  enable_testing()

  function(mpf_add_test target_name)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE SummonSoftwareLabs::MultipathFabric)
    target_include_directories(${target_name}
      PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    if(MPF_ENABLE_ANALYZE AND MSVC)
      # Library, tools and examples are held to the analyzer's default 16 KiB
      # frame threshold. Test translation units contain deliberately exhaustive
      # scenario functions, so they are given a larger -- but still modest --
      # budget instead of scattering suppressions through the tests.
      target_compile_options(${target_name} PRIVATE /analyze:stacksize32768)
    endif()
    add_test(NAME ${target_name} COMMAND ${target_name})
  endfunction()

  mpf_add_test(mpf_tests_core
    tests/test_main.cpp
    tests/test_identities.cpp
    tests/test_lifecycle.cpp
    tests/test_thresholds.cpp
    tests/test_membership.cpp
    tests/test_authority.cpp
  )

  mpf_add_test(mpf_tests_state
    tests/test_main.cpp
    tests/test_invalidation.cpp
    tests/test_races.cpp
    tests/test_property.cpp
  )

  mpf_add_test(mpf_tests_io
    tests/test_main.cpp
    tests/test_limits.cpp
    tests/test_persistence.cpp
    tests/test_wire.cpp
    tests/test_adversarial.cpp
  )

  if(MPF_BUILD_TOOLS)
    mpf_add_test(mpf_tests_distributed
      tests/test_main.cpp
      tests/test_distributed.cpp
    )
    target_compile_definitions(mpf_tests_distributed PRIVATE
      MPF_COORDINATOR_EXECUTABLE="$<TARGET_FILE:mpf_coordinator>"
      MPF_PUBLISHER_EXECUTABLE="$<TARGET_FILE:mpf_publisher>"
    )
    add_dependencies(mpf_tests_distributed mpf_coordinator mpf_publisher)
  endif()
endif()

# AddressSanitizer deploys its runtime as a DLL; place it next to the built
# executables so the sanitized binaries can load it without touching PATH.
if(MPF_ENABLE_ASAN AND MSVC)
  get_filename_component(MPF_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
  add_custom_target(asan-runtime ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MPF_COMPILER_BIN_DIR}/clang_rt.asan_dynamic-x86_64.dll"
            "${CMAKE_BINARY_DIR}/clang_rt.asan_dynamic-x86_64.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MPF_COMPILER_BIN_DIR}/clang_rt.asan_dbg_dynamic-x86_64.dll"
            "${CMAKE_BINARY_DIR}/clang_rt.asan_dbg_dynamic-x86_64.dll"
    VERBATIM
    COMMENT "Deploying the AddressSanitizer runtime next to the built binaries"
  )
endif()

install(FILES LICENSE README.md
  DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/MultipathFabric
  OPTIONAL
)
