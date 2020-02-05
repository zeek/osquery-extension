cmake_minimum_required(VERSION 3.16.3)
project("zeek_audisp")

function(zeekAgentComponentsAudisp)
  add_library("${PROJECT_NAME}"
    include/zeek/iaudispconsumer.h
    
    src/audispconsumer.h
    src/audispconsumer.cpp

    src/audit_utils.h
    src/audit_utils.cpp

    src/iauparseinterface.h
    src/auparseinterface.h
    src/auparseinterface.cpp

    src/iaudispproducer.h
    src/audispsocketreader.h
    src/audispsocketreader.cpp
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

    PUBLIC
      zeek_utils
      thirdparty_audit
      ${CMAKE_THREAD_LIBS_INIT}
      ${CMAKE_DL_LIBS}
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp

      tests/mockedauparseinterface.h
      tests/mockedauparseinterface.cpp

      tests/audit_utils.cpp
      tests/audisp_records.cpp
      tests/audisp_events.cpp

      tests/mockedaudispproducer.h
      tests/mockedaudispproducer.cpp
  )
endfunction()

zeekAgentComponentsAudisp()
