cmake_minimum_required(VERSION 3.16.3)

if("${CMAKE_SYSTEM_NAME}" STREQUAL "")
  set(CMAKE_SYSTEM_NAME "${CMAKE_HOST_SYSTEM_NAME}")
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

option(ZEEK_AGENT_ENABLE_TESTS "Set to ON to build the tests")
option(ZEEK_AGENT_ENABLE_INSTALL "Set to ON to generate the install directives")

if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  option(ZEEK_AGENT_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")
else()
  set(ZEEK_AGENT_ENABLE_SANITIZERS OFF CACHE BOOL "Sanitizers are not supported on Windows" FORCE)
endif()

option(ZEEK_AGENT_ENABLE_DOCUMENTATION "Set to ON to generate the Doxygen documentation")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
  set(ZEEK_AGENT_CODESIGN_IDENTITY "" CACHE STRING "Codesign identity")
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  set(ZEEK_AGENT_ZEEK_COMPATIBILITY "3.1" CACHE STRING "Latest Broker version is forced when building on Windows" FORCE)

else()
  set(ZEEK_AGENT_ZEEK_COMPATIBILITY "3.1" CACHE STRING "Build with either '3.0' or '3.1' Zeek server compatibility")
  if("${ZEEK_AGENT_ZEEK_COMPATIBILITY}" STREQUAL "3.0")
    message(STATUS "zeek-agent: Building with Zeek 3.0 compatibility")
  elseif("${ZEEK_AGENT_ZEEK_COMPATIBILITY}" STREQUAL "3.1")
    message(STATUS "zeek-agent: Building with Zeek >= 3.1 compatibility")
  else()
    message(FATAL_ERROR "zeek-agent: Invalid value specified for ZEEK_AGENT_ZEEK_COMPATIBILITY: ${ZEEK_AGENT_ZEEK_COMPATIBILITY}. Valid values: 3.0, 3.1")
  endif()
endif()

if(TARGET osqueryd)
  message(STATUS "zeek-agent: Building with osquery support; disabling the custom toolchain")
  set(ZEEK_AGENT_TOOLCHAIN_PATH "" CACHE PATH "Not supported when building with osquery support" FORCE)

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    message(STATUS "zeek-agent: Building with osquery support; enabling libc++ support")
    set(ZEEK_AGENT_ENABLE_LIBCPP ON CACHE BOOL "Forced when building with osquery support on Linux" FORCE)
  else()
    set(ZEEK_AGENT_ENABLE_LIBCPP OFF CACHE BOOL "Only supported on Linux" FORCE)
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows" AND "${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    # osquery still depends on some of the legacy pre-built binaries shipped by the previous upstream.
    # Keep debug builds disabled until the Windows build is fully migrated to the 'source' dependency
    # layer
    message(FATAL_ERROR "osquery does not support Debug builds on Windows")
  endif()

else()
  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(ZEEK_AGENT_TOOLCHAIN_PATH "" CACHE PATH "Toolchain path")
  else()
    set(ZEEK_AGENT_TOOLCHAIN_PATH "" CACHE PATH "Only supported on macOS and Linux" FORCE)
  endif()

  if(NOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" STREQUAL "")
    if(NOT EXISTS "${ZEEK_AGENT_TOOLCHAIN_PATH}")
      message(FATAL_ERROR "zeek-agent: The specified toolchain path is not valid: ${ZEEK_AGENT_TOOLCHAIN_PATH}")
    endif()

    message(STATUS "zeek-agent: Using toolchain path '${ZEEK_AGENT_TOOLCHAIN_PATH}'")

    set(CMAKE_C_COMPILER "${ZEEK_AGENT_TOOLCHAIN_PATH}/usr/bin/clang" CACHE PATH "Path to the C compiler" FORCE)
    set(CMAKE_CXX_COMPILER "${ZEEK_AGENT_TOOLCHAIN_PATH}/usr/bin/clang++" CACHE PATH "Path to the C++ compiler" FORCE)
    set(CMAKE_SYSROOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" CACHE PATH "CMake sysroot for find_package scripts")

    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
      set(ZEEK_AGENT_ENABLE_LIBCPP ON CACHE BOOL "Forced when building with the custom toolchain on Linux" FORCE)
    else()
      set(ZEEK_AGENT_ENABLE_LIBCPP OFF CACHE BOOL "Only supported on Linux" FORCE)
    endif()

  else()
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
      set(ZEEK_AGENT_ENABLE_LIBCPP OFF CACHE BOOL "Set to ON to enable libc++ support")
    else()
      set(ZEEK_AGENT_ENABLE_LIBCPP OFF CACHE BOOL "Only supported on Linux" FORCE)
    endif()
  endif()
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
