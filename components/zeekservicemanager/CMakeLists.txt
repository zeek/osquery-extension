cmake_minimum_required(VERSION 3.16.3)
project("zeek_service_manager")

function(zeekAgentComponentsServiceManager)
  add_library("${PROJECT_NAME}"
    include/zeek/izeekservicemanager.h

    src/zeekservicemanager.h
    src/zeekservicemanager.cpp

    src/zeekservicemanagertableplugin.h
    src/zeekservicemanagertableplugin.cpp
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
      zeek_logger
  )
endfunction()

zeekAgentComponentsServiceManager()
