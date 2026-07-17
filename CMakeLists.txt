cmake_minimum_required(VERSION 3.22.1)
project(ipad-manager LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(IPAD_BUILD_TESTS "Build IPAd Manager tests" ON)

add_subdirectory(common)
add_subdirectory(ipad_managerd)
add_subdirectory(ipad_worker)
add_subdirectory(ipadctl)

if(IPAD_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
