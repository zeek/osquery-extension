cmake_minimum_required(VERSION 3.16.3)
project("zeek_utils")

function(zeekAgentComponentsUtils)
  add_library("${PROJECT_NAME}"
    include/zeek/status.h

    include/zeek/system_identifiers.h
    src/system_identifiers.cpp
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
  )

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )

  target_link_libraries("${PROJECT_NAME}" PUBLIC
    zeek_agent_cxx_settings
  )
endfunction()

zeekAgentComponentsUtils()
