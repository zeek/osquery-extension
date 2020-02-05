cmake_minimum_required(VERSION 3.16.3)
project("zeek_utils")

function(zeekAgentComponentsUtils)
  add_library("${PROJECT_NAME}" INTERFACE)

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )

  target_link_libraries("${PROJECT_NAME}" INTERFACE
    zeek_agent_cxx_settings
  )
endfunction()

zeekAgentComponentsUtils()
