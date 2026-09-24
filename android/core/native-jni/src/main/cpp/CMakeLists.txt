cmake_minimum_required(VERSION 3.22.1)

project(kurdistan_jni LANGUAGES C)

if(NOT DEFINED KVPN_GO_BRIDGE_ROOT)
    message(FATAL_ERROR "The generated Go bridge root was not provided")
endif()

set(KVPN_GO_BRIDGE_SO "${KVPN_GO_BRIDGE_ROOT}/${ANDROID_ABI}/libkurdistan_bridge.so")
if(NOT EXISTS "${KVPN_GO_BRIDGE_SO}")
    message(FATAL_ERROR "The generated Go bridge is missing: ${KVPN_GO_BRIDGE_SO}")
endif()

add_library(kurdistan_bridge SHARED IMPORTED)
set_target_properties(
    kurdistan_bridge
    PROPERTIES
    IMPORTED_LOCATION "${KVPN_GO_BRIDGE_SO}"
    IMPORTED_SONAME "libkurdistan_bridge.so"
)

add_library(kurdistan_jni SHARED kvpn_jni.c kvpn_durable_fs.c kvpn_durable_fs_jni.c kvpn_output_gate_v1.c kvpn_bootstrap_binding_jni.c kvpn_android_callbacks.c kvpn_tun_proof.c kvpn_production_facade_v1.c kvpn_production_jni_v1.c kvpn_production_spans_v1.c)
target_sources(kurdistan_jni PRIVATE kvpn_stream_facade_v1.c kvpn_stream_jni_v1.c kvpn_platform_finalize_v1.c)
target_sources(kurdistan_jni PRIVATE kvpn_maintenance_facade_v1.c kvpn_maintenance_jni_v1.c)

if(KVPN_ANDROID_PLATFORM_INTERNAL_V1)
    configure_file(../../internal/cpp/kvpn_task7_maintenance_fixture_jni.c
        "${CMAKE_CURRENT_BINARY_DIR}/task7_maintenance_fixture.c" COPYONLY)
    target_sources(kurdistan_jni PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/task7_maintenance_fixture.c")
    configure_file(../../internal/cpp/kvpn_task7_installed_fixture_jni.c
        "${CMAKE_CURRENT_BINARY_DIR}/task7_installed_fixture.c" COPYONLY)
    target_sources(kurdistan_jni PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/task7_installed_fixture.c")
    # A build-owned copy avoids Ninja encoding this outside-source-tree file's
    # absolute Windows path into its object path. CMake tracks the original input.
    configure_file(../../internal/cpp/kvpn_android_platform_conformance.c
        "${CMAKE_CURRENT_BINARY_DIR}/platform_vm.c" COPYONLY)
    target_sources(kurdistan_jni PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/platform_vm.c")
    configure_file(../../internal/cpp/kvpn_conformance_internal_jni.c
        "${CMAKE_CURRENT_BINARY_DIR}/conformance_internal.c" COPYONLY)
    target_sources(kurdistan_jni PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/conformance_internal.c")
    target_compile_definitions(kurdistan_jni PRIVATE KVPN_ANDROID_PLATFORM_INTERNAL_V1=1)
endif()
target_include_directories(kurdistan_jni PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

target_include_directories(kurdistan_jni PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../cmd/kandroidbridge")

target_compile_features(kurdistan_jni PRIVATE c_std_17)
target_compile_options(
    kurdistan_jni
    PRIVATE
    -Wall
    -Wextra
    -Werror
    -fvisibility=hidden
    -fstack-protector-strong
    "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
    "-fdebug-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
    "-fmacro-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
    "-ffile-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=."
    "-fdebug-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=."
    "-fmacro-prefix-map=${CMAKE_CURRENT_BINARY_DIR}=."
)
target_link_options(
    kurdistan_jni
    PRIVATE
    -Wl,--build-id=none
    -Wl,--no-undefined
    -Wl,-z,relro
    -Wl,-z,now
)
target_link_libraries(kurdistan_jni PRIVATE kurdistan_bridge)
