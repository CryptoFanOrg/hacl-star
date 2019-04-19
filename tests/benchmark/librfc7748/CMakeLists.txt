project(librfc7748 LANGUAGES C ASM)
cmake_minimum_required(VERSION 3.12)

set(RFC7748_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../rfc7748_src CACHE PATH "Where to find the RFC 7748 reference implementation sources.")
get_filename_component(RFC7748_DIR ${RFC7748_DIR} REALPATH)
message("-- Using RFC 7748 reference implementation at ${RFC7748_DIR}")

add_library(rfc7748 STATIC)
target_include_directories(rfc7748 PUBLIC ${RFC7748_DIR})
target_compile_options(rfc7748 PRIVATE )
target_compile_definitions(rfc7748 PRIVATE _BSD_SOURCE _DEFAULT_SOURCE)

# if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
#   target_compile_definitions(rfc7748 PUBLIC __USE_MINGW_ANSI_STDIO)
# else(CMAKE_SYSTEM_NAME STREQUAL "Windows")
#   target_compile_options(rfc7748 PUBLIC -fPIC)
# endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_sources(rfc7748 PRIVATE
  ${RFC7748_DIR}/fp25519_x64.c
  ${RFC7748_DIR}/fp448_x64.c
  ${RFC7748_DIR}/x25519_x64.c
  ${RFC7748_DIR}/x448_x64.c
)
