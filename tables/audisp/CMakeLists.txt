cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesAudisp)
  add_library(zeek_audisp_tables
    include/zeek/audispservicefactory.h
    src/audispservicefactory.cpp

    src/socketeventstableplugin.h
    src/socketeventstableplugin.cpp

    src/processeventstableplugin.h
    src/processeventstableplugin.cpp

    src/audispservice.h
    src/audispservice.cpp
  )

  target_include_directories(zeek_audisp_tables PRIVATE
    include
  )

  target_include_directories(zeek_audisp_tables SYSTEM INTERFACE
    include
  )

  target_link_libraries(zeek_audisp_tables PUBLIC
    zeek_audisp
    zeek_database
    zeek_configuration
    zeek_service_manager
  )

  target_link_libraries(zeek_tables INTERFACE zeek_audisp_tables)

  generateZeekAgentTest(
    SOURCE_TARGET
      "zeek_audisp_tables"

    SOURCES
      tests/main.cpp

      tests/utils.h
      tests/utils.cpp

      tests/processeventstableplugin.cpp
      tests/socketeventstableplugin.cpp
  )
endfunction()

zeekAgentTablesAudisp()
