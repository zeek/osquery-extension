cmake_minimum_required(VERSION 3.16.3)
project("zeek_endpoint_security")

function(zeekAgentComponentsEndpointSecurity)
  add_library("${PROJECT_NAME}"
    include/zeek/iendpointsecurityconsumer.h
    
    src/endpointsecurityconsumer.h
    src/endpointsecurityconsumer.cpp
  )

  importEndpointSecurity()

  target_link_libraries("${PROJECT_NAME}"
    PRIVATE
      zeek_agent_cxx_settings

    PUBLIC
      zeek_utils
      zeek_logger
      zeek_configuration
      thirdparty_endpointsecurity
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
  )

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )
endfunction()

function(importEndpointSecurity)
  find_library(endpointsecurity_lib_path "libEndpointSecurity.tbd"
    PATHS "${CMAKE_OSX_SYSROOT}/usr/lib"
  )

  if("${endpointsecurity_lib_path}" STREQUAL "endpointsecurity_lib_path-NOTFOUND")
    message(FATAL_ERROR "The EndpointSecurity library was not found")
  endif()

  add_library(thirdparty_endpointsecurity STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_endpointsecurity PROPERTIES
    IMPORTED_LOCATION "${endpointsecurity_lib_path}"
  )
endfunction()

zeekAgentComponentsEndpointSecurity()

