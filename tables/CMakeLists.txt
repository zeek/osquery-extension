cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTables)
  add_library(zeek_tables INTERFACE)

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    add_subdirectory("audisp")
  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    add_subdirectory("endpointsecurity")
  endif()

  add_subdirectory("host_information")
endfunction()

zeekAgentTables()
