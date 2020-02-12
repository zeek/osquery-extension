cmake_minimum_required(VERSION 3.16.3)
project("zeek_endpoint_security")

function(zeekAgentComponentsEndpointSecurity)
  add_library("${PROJECT_NAME}"
    include/zeek/iendpointsecurityconsumer.h
    
    src/endpointsecurityconsumer.h
    src/endpointsecurityconsumer.cpp
  )

  importLibraries()

  target_link_libraries("${PROJECT_NAME}"
    PRIVATE
      zeek_agent_cxx_settings

    PUBLIC
      zeek_utils
      zeek_logger
      zeek_configuration

      thirdparty_endpointsecurity
      thirdparty_bsm
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
  )

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp
      tests/endpointsecurityconsumer.cpp
  )
endfunction()

function(importExternalLibrary target_name library_name)
  set(library_path_var "${library_name}_path")

  find_library("${library_path_var}" "${library_name}"
    PATHS "${CMAKE_OSX_SYSROOT}/usr/lib"
  )

  if("${${library_path_var}}" STREQUAL "${library_path_var}-NOTFOUND")
    message(FATAL_ERROR "The ${target_name} (${library_name}) library was not found")
  endif()

  add_library("thirdparty_${target_name}" STATIC IMPORTED GLOBAL)
  set_target_properties("thirdparty_${target_name}" PROPERTIES
    IMPORTED_LOCATION "${${library_path_var}}"
  )
endfunction()

function(importLibraries)
  importExternalLibrary("endpointsecurity" "libEndpointSecurity.tbd")
  importExternalLibrary("bsm" "libbsm.tbd")
endfunction()

zeekAgentComponentsEndpointSecurity()

