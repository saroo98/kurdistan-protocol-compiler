cmake_minimum_required(VERSION 3.22.1)

project(kurdistan_jni LANGUAGES C)

if(NOT DEFINED KVPN_GO_BRIDGE_SO OR NOT EXISTS "${KVPN_GO_BRIDGE_SO}")
    message(FATAL_ERROR "The generated Go bridge is missing: ${KVPN_GO_BRIDGE_SO}")
endif()

add_library(kurdistan_bridge SHARED IMPORTED)
set_target_properties(
    kurdistan_bridge
    PROPERTIES
    IMPORTED_LOCATION "${KVPN_GO_BRIDGE_SO}"
    IMPORTED_SONAME "libkurdistan_bridge.so"
)

add_library(kurdistan_jni SHARED kvpn_jni.c)

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
