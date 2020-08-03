cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesEndpointSecurity)
  add_library(zeek_endpoint_security_tables
    include/zeek/endpointsecurityservicefactory.h
    src/endpointsecurityservicefactory.cpp

    src/processeventstableplugin.h
    src/processeventstableplugin.cpp

    src/fileeventstableplugin.h
    src/fileeventstableplugin.cpp

    src/endpointsecurityservice.h
    src/endpointsecurityservice.cpp
  )

  target_include_directories(zeek_endpoint_security_tables PRIVATE
    include
  )

  target_include_directories(zeek_endpoint_security_tables SYSTEM INTERFACE
    include
  )

  target_link_libraries(zeek_endpoint_security_tables PUBLIC
    zeek_endpoint_security
    zeek_database
    zeek_configuration
    zeek_service_manager
  )

  target_link_libraries(zeek_tables INTERFACE zeek_endpoint_security_tables)

  generateZeekAgentTest(
    SOURCE_TARGET
      "zeek_endpoint_security_tables"

    SOURCES
      tests/main.cpp
      tests/processeventstableplugin.cpp
      tests/fileeventstableplugin.cpp
  )
endfunction()

zeekAgentTablesEndpointSecurity()
