cmake_minimum_required(VERSION 3.16.3)
project("zeek_database")

function(zeekAgentComponentsDatabase)
  add_library("${PROJECT_NAME}"
    include/zeek/ivirtualdatabase.h
    include/zeek/ivirtualtable.h

    src/virtualdatabase.h
    src/virtualdatabase.cpp

    src/virtualtablemodule.h
    src/virtualtablemodule.cpp

    src/sqlite_utils.h
    src/sqlite_utils.cpp
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
  )

  target_include_directories("${PROJECT_NAME}"
    SYSTEM INTERFACE include
  )

  find_package(Threads REQUIRED)

  target_link_libraries("${PROJECT_NAME}"
    PRIVATE
      zeek_agent_cxx_settings
      thirdparty_sqlite
      ${CMAKE_DL_LIBS}
      ${CMAKE_THREAD_LIBS_INIT}

    PUBLIC
      zeek_utils
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp
      tests/virtualtablemodule.cpp
      tests/virtualdatabase.cpp
  )
endfunction()

zeekAgentComponentsDatabase()
