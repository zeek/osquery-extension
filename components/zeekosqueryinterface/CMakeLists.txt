cmake_minimum_required(VERSION 3.16.3)
project("zeek_osquery_interface")

function(zeekAgentComponentsOsqueryInterface)
  add_library("${PROJECT_NAME}"
    include/zeek/iosqueryinterface.h

    src/osqueryinterface.h
    src/osqueryinterface.cpp

    src/osquerytableplugin.h
    src/osquerytableplugin.cpp

    src/utils.h
    src/utils.cpp
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
      osquery_sdk_pluginsdk
      osquery_extensions_extensionsinterface
      osquery_extensions
      external_options
  )
endfunction()

zeekAgentComponentsOsqueryInterface()
