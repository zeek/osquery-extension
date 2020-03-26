cmake_minimum_required(VERSION 3.14)
project("broker")

function(zeekAgentLibrariesBroker)
  #
  # Mixed settings
  #

  # The following settings will not correctly show up in the Broker or CAF group
  # due to missing prefix
  message(WARNING "Some Broker/CAF configuration settings are not using the name prefix. Settings may leak to other libraries!")

  set(OPENSSL_LIBRARIES "thirdparty_openssl" CACHE STRING "Broker/CAF: OpenSSL library (forced)" FORCE)
  set(OPENSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}" CACHE STRING "Broker/CAF: OpenSSL include folder (forced, unused)" FORCE)
  set(DISABLE_PYTHON_BINDINGS ON CACHE BOOL "Broker/CAF: Disable Broker Python bindings (forced)" FORCE)
  set(ENABLE_STATIC_ONLY ON CACHE BOOL "Broker/CAF: Disable shared libraries (forced)" FORCE)

  #
  # Broker settings
  #

  set(BROKER_DISABLE_TESTS ON CACHE BOOL "Broker/CAF: Disable tests (forced)" FORCE)
  set(BROKER_DISABLE_DOCS ON CACHE BOOL "Broker/CAF: Disable docs (forced)" FORCE)
  set(BROKER_DISABLE_TOOLS ON CACHE BOOL "Broker/CAF: Disable Broker tools (forced)" FORCE)
  set(BROKER_HAS_STD_FILESYSTEM ON CACHE BOOL "Broker/CAF: Attempt to skip manual checks (forced)" FORCE)

  #
  # CAF settings
  #

  # These do not seem to work correctly, and will not remove shared targets
  set(CAF_BUILD_STATIC_ONLY ON CACHE BOOL "Broker/CAF: Disable shared libraries 1 (forced)" FORCE)
  set(CAF_BUILD_STATIC ON CACHE BOOL "Broker/CAF: Disable shared libraries 2 (forced)" FORCE)

  add_subdirectory("src" EXCLUDE_FROM_ALL)

  if(TARGET "libcaf_core" OR TARGET "libcaf_io" OR TARGET "libcaf_openssl")
    message(WARNING "The CAF project has generated non-static targets despite the build settings")
  endif()

  add_library(thirdparty_actorframework INTERFACE)
  foreach(libcaf_target libcaf_core_static libcaf_io_static libcaf_openssl_static)
    # We can't use the PRIVATE keyword because the project is calling target_link_libraries
    # without any visibility setting
    target_link_libraries("${libcaf_target}"
      zeek_agent_libraries_settings
    )

    # Prevent issues by defining WIN32_LEAN_AND_MEAN where it is missing
    target_compile_definitions("${libcaf_target}" PRIVATE WIN32_LEAN_AND_MEAN)

    target_link_libraries(thirdparty_actorframework INTERFACE
      "${libcaf_target}"
    )
  endforeach()

  add_library(thirdparty_broker INTERFACE)
  target_link_libraries(thirdparty_broker INTERFACE
    broker_static
  )

  find_library(std_cpp_fs_path "c++fs")
  if(NOT "${std_cpp_fs_path}" STREQUAL "std_cpp_fs_path-NOTFOUND")
    target_link_libraries(thirdparty_broker INTERFACE
      "${std_cpp_fs_path}"
    )
  endif()

  # We can't use the PRIVATE keyword because the project is calling target_link_libraries
  # without any visibility setting
  target_link_libraries(broker_static
    zeek_agent_libraries_settings
  )

  # Prevent issues by defining WIN32_LEAN_AND_MEAN where it is missing in Broker
  target_compile_definitions(broker_static PRIVATE WIN32_LEAN_AND_MEAN)

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

  # CAF and Broker may not compile correctly with debug symbols enabled without increasing
  # the section limit
  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows" AND ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo"))
    foreach(library libcaf_core_static libcaf_io_static libcaf_openssl_static broker_static)
      target_compile_options("${library}" PRIVATE
        /bigobj
      )
    endforeach()
  endif()
endfunction()

zeekAgentLibrariesBroker()
