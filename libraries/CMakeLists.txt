cmake_minimum_required(VERSION 3.14)

function(zeekAgentLibraries)
  add_library(zeek_agent_libraries_settings INTERFACE)

  if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    target_compile_options(zeek_agent_libraries_settings INTERFACE
      -Wno-error
    )

  else()
    target_compile_options(zeek_agent_libraries_settings INTERFACE
      /W0
      /WX-
    )
  endif()

  if("${ZEEK_AGENT_ZEEK_COMPATIBILITY}" STREQUAL "3.0")
    add_subdirectory("broker-legacy")
  else()
    add_subdirectory("broker")
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    add_subdirectory("audit")
  endif()

  add_subdirectory("catch2")
  add_subdirectory("xxhash")

  # If we are being built under osquery, then we may already have
  # some of these libraries available

  if(NOT TARGET thirdparty_sqlite)
    add_subdirectory("sqlite")
  endif()

  if(NOT TARGET thirdparty_rapidjson)
    add_subdirectory("rapidjson")
  endif()

  if(NOT TARGET thirdparty_openssl)
    add_subdirectory("zlib")
    add_subdirectory("openssl")
  endif()
endfunction()

zeekAgentLibraries()
