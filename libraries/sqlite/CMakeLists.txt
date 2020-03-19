cmake_minimum_required(VERSION 3.14)

function(zeekAgentLibrariesSqlite)
  add_subdirectory("src")

  target_link_libraries(thirdparty_sqlite PRIVATE
    zeek_agent_c_settings
    zeek_agent_libraries_settings
  )

  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    target_link_libraries(thirdparty_sqlite PRIVATE
      dl
    )
  endif()
endfunction()

zeekAgentLibrariesSqlite()
