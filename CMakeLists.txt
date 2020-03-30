cmake_minimum_required(VERSION 3.5)

project(oqs-engine
        VERSION "0.0.1"
        LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)
if(WIN32)
    set(CMAKE_GENERATOR_CC cl)
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()
include(.CMake/compiler_flags.cmake)

if(NOT DEFINED OPENSSL_ROOT_DIR)
    if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Darwin")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@1.1")
    elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
        set(OPENSSL_ROOT_DIR "/usr")
    endif()
endif()
find_package(OpenSSL 1.1.0 REQUIRED)

include(third_party/liboqs/add_lib.cmake)

add_subdirectory(src)
add_subdirectory(tests)

find_package(Doxygen)
if(DOXYGEN_FOUND)
    add_custom_target(
        gen_docs
        COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_SOURCE_DIR}/.Doxyfile
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        COMMENT "Generate API documentation with Doxygen."
        USES_TERMINAL)
endif()
