cmake_minimum_required(VERSION 3.16.3)

function(zeekAgentTablesHostInformationTablePlugin)
  add_library(zeek_host_information_table
    include/zeek/ihostinformationtableplugin.h

    src/hostinformationtableplugin.h
    src/hostinformationtableplugin.cpp

    src/osversion.h
  )

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    target_sources(zeek_host_information_table PRIVATE
      src/osversion_linux.cpp
    )

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    target_sources(zeek_host_information_table PRIVATE
      src/osversion_macos.mm
    )

    target_link_libraries(zeek_host_information_table PUBLIC
      "-framework Cocoa"

    )
  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_sources(zeek_host_information_table PRIVATE
      src/osversion_windows.cpp
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  target_include_directories(zeek_host_information_table PRIVATE
    include
  )

  target_include_directories(zeek_host_information_table SYSTEM INTERFACE
    include
  )

  target_link_libraries(zeek_host_information_table PUBLIC
    zeek_database
    thirdparty_broker
  )

  target_link_libraries(zeek_tables INTERFACE zeek_host_information_table)
endfunction()

zeekAgentTablesHostInformationTablePlugin()
