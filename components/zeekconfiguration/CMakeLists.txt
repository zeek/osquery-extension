cmake_minimum_required(VERSION 3.16.3)
project("zeek_configuration")

function(zeekAgentComponentsConfiguration)
  add_library("${PROJECT_NAME}"
    include/zeek/izeekconfiguration.h

    src/zeekconfiguration.h
    src/zeekconfiguration.cpp

    src/configurationchecker.h
    src/configurationchecker.cpp

    src/zeekconfigurationtableplugin.h
    src/zeekconfigurationtableplugin.cpp
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
  )

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )

  target_link_libraries("${PROJECT_NAME}"
    PRIVATE
      zeek_agent_cxx_settings

    PUBLIC
      zeek_utils
      zeek_database
      thirdparty_rapidjson
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp
      tests/configurationchecker.cpp
      tests/zeekconfiguration.cpp
  )
endfunction()

zeekAgentComponentsConfiguration()
