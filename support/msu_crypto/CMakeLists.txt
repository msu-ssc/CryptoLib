cmake_minimum_required(VERSION 3.16)
project(msu_crypto C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Build CryptoLib as a subproject in this build tree.
# Force safer defaults so we don’t inherit -Werror or fuzz sanitizer flags from the parent.
set(ENABLE_FUZZING OFF CACHE BOOL "Disable fuzz targets for msu_crypto build" FORCE)
set(CMAKE_C_FLAGS "-Wall -Wextra -g -O0" CACHE STRING "C flags without -Werror" FORCE)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../.. ${CMAKE_BINARY_DIR}/cryptolib_build)

add_executable(msu_crypto msu_crypto.c)
target_include_directories(msu_crypto PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../../include)
target_link_libraries(msu_crypto PRIVATE crypto)

# Relax warnings for the bundled crypto target to avoid -Werror breaks in downstream builds.
set_property(TARGET crypto APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-error -Wno-error=maybe-uninitialized")
set_property(TARGET msu_crypto APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-error -Wno-error=maybe-uninitialized")
