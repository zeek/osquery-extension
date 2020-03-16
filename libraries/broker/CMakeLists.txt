cmake_minimum_required(VERSION 3.14)
project("broker")

function(zeekAgentLibrariesBroker)
  message(WARNING "Some Broker/CAF configuration settings are not using the name prefix. Settings may leak to other libraries!")

  set(OPENSSL_LIBRARIES "thirdparty_openssl" CACHE STRING "Broker/CAF: OpenSSL library (forced)" FORCE)
  set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}" CACHE STRING "Broker/CAF: OpenSSL include folder (forced, unused)" FORCE)
  set(BROKER_DISABLE_TESTS ON CACHE BOOL "Broker/CAF: Disable tests (forced)" FORCE)
  set(BROKER_DISABLE_DOCS ON CACHE BOOL "Broker/CAF: Disable docs (forced)" FORCE)
  set(BROKER_DISABLE_TOOLS ON CACHE BOOL "Broker/CAF: Disable Broker tools (forced)" FORCE)
  set(DISABLE_PYTHON_BINDINGS ON CACHE BOOL "Broker/CAF: Disable Broker Python bindings (forced)" FORCE)
  set(ENABLE_STATIC_ONLY ON CACHE BOOL "Broker/CAF: Disable shared libraries (forced)" FORCE)

  # These do not seem to work correctly, and will not remove shared targets
  set(CAF_BUILD_STATIC_ONLY ON CACHE BOOL "Broker/CAF: Disable shared libraries 1 (forced)" FORCE)
  set(CAF_BUILD_STATIC ON CACHE BOOL "Broker/CAF: Disable shared libraries 2 (forced)" FORCE)

  add_subdirectory("src" EXCLUDE_FROM_ALL)

  if(TARGET "libcaf_core" OR TARGET "libcaf_io" OR TARGET "libcaf_openssl")
    message(WARNING "The CAF project has generated non-static targets despite the build settings")
  endif()

  add_library(thirdparty_actorframework INTERFACE)
  target_link_libraries(thirdparty_actorframework INTERFACE
    libcaf_core
    libcaf_io
    libcaf_openssl
  )

  add_library(thirdparty_broker INTERFACE)
  target_link_libraries(thirdparty_broker INTERFACE
    broker_static
  )

  # It does not seem like the Broker project is correctly attaching the include directories
  # to the target; issue a warning and manually fix the build
  get_target_property(broker_include_dirs "broker_static" INTERFACE_INCLUDE_DIRECTORIES)
  if("${broker_include_dirs}" STREQUAL "broker_include_dirs-NOTFOUND")
    message(WARNING "The Broker project is not correctly exporting the include directories from the target")

    get_target_property(broker_include_dirs "broker_static" INCLUDE_DIRECTORIES)
    target_include_directories(thirdparty_broker INTERFACE
      "${broker_include_dirs}"
    )
  endif()
endfunction()

zeekAgentLibrariesBroker()
