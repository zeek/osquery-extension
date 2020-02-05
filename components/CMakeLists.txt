cmake_minimum_required(VERSION 3.16.3)

function(zeekComponents)
  add_subdirectory("zeekutils")
  add_subdirectory("zeekdatabase")
  add_subdirectory("zeekaudisp")
  add_subdirectory("zeeklogger")
  add_subdirectory("zeekservicemanager")
  add_subdirectory("zeekconfiguration")

  if(TARGET osqueryd)
    add_subdirectory("zeekosqueryinterface")
  endif()
endfunction()

zeekComponents()
