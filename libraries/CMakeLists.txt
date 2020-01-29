cmake_minimum_required(VERSION 3.14)

function(zeekAgentLibraries)
  add_library(zeek_agent_libraries_settings INTERFACE)
  target_compile_options(zeek_agent_libraries_settings INTERFACE
    -Wno-error
  )

  if("${ZEEK_AGENT_ZEEK_COMPATIBILITY}" STREQUAL "3.0")
    add_subdirectory("broker-legacy")
  else()
    add_subdirectory("broker")
  endif()

  add_subdirectory("catch2")
  add_subdirectory("audit")
  add_subdirectory("xxhash")

  # If we are being built under osquery, then we may already have
  # some of these libraries available

  if(NOT TARGET thirdparty_sqlite)
    add_subdirectory("sqlite")
  endif()

  if(NOT TARGET thirdparty_rapidjson)
    add_subdirectory("rapidjson")
  endif()

  # OpenSSL is only built if we are building zeek-agent alone with
  # the custom toolchain
  if(NOT TARGET osqueryd)
    if(NOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" STREQUAL "")
      add_subdirectory("zlib")
      add_subdirectory("openssl")

    else()
      find_package(OpenSSL REQUIRED)

      add_library(thirdparty_openssl INTERFACE)
      target_link_libraries(thirdparty_openssl INTERFACE
        OpenSSL::SSL
        OpenSSL::Crypto
      )
    endif()
  endif()
endfunction()

zeekAgentLibraries()
