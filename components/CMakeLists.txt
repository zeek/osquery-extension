cmake_minimum_required(VERSION 3.16.3)

function(zeekComponents)
  add_subdirectory("zeekutils")
  add_subdirectory("zeekdatabase")
  add_subdirectory("zeeklogger")
  add_subdirectory("zeekservicemanager")
  add_subdirectory("zeekconfiguration")

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    add_subdirectory("zeekaudisp")
  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    add_subdirectory("zeekendpointsecurity")
  endif()

  if(TARGET osqueryd)
    add_subdirectory("zeekosqueryinterface")
  endif()
endfunction()

zeekComponents()
