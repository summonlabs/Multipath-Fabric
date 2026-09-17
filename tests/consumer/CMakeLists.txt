cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer of the installed MultipathFabric package.
# This project deliberately does not reference the Multipath Fabric source tree:
# it must configure, compile and link using installed artifacts only.
project(MultipathFabricConsumer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(MultipathFabric CONFIG REQUIRED)

# Fail fast when the documented imported target is missing.
if(NOT TARGET SummonSoftwareLabs::MultipathFabric)
  message(FATAL_ERROR "SummonSoftwareLabs::MultipathFabric was not exported")
endif()

add_executable(mpf_consumer consumer.cpp)
target_link_libraries(mpf_consumer PRIVATE SummonSoftwareLabs::MultipathFabric)
