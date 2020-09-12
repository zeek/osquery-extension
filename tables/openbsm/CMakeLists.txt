cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesOpenbsm)
  add_library(zeek_openbsm_tables
    include/zeek/openbsmservicefactory.h
    src/openbsmservicefactory.cpp

    src/openbsmservice.h
    src/openbsmservice.cpp
    src/socketeventstableplugin.cpp
    src/socketeventstableplugin.h
  )

  target_include_directories(zeek_openbsm_tables PRIVATE
    include
  )

  target_include_directories(zeek_openbsm_tables SYSTEM INTERFACE
    include
  )

  target_link_libraries(zeek_openbsm_tables PUBLIC
    zeek_openbsm
    zeek_database
    zeek_configuration
    zeek_service_manager
  )

  target_link_libraries(zeek_tables INTERFACE zeek_openbsm_tables)

  generateZeekAgentTest(
    SOURCE_TARGET
      "zeek_openbsm_tables"

    SOURCES
      tests/main.cpp
      tests/socketeventstableplugin.cpp
  )
endfunction()

zeekAgentTablesOpenbsm()
