cmake_minimum_required(VERSION 3.16.3)

include("cmake/options.cmake")
project("zeek-agent")

if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "")
  set(CMAKE_SYSTEM_PROCESSOR "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()

include("cmake/version.cmake")
include("cmake/flags.cmake")
include("cmake/utils.cmake")
include("cmake/tests.cmake")
include("cmake/ccache.cmake")
include("cmake/codesigning.cmake")

function(zeekAgent)
  generateSettingsTarget()
  generateRootZeekTestTarget()

  add_subdirectory("libraries")
  add_subdirectory("components")
  add_subdirectory("tables")

  set(target_name_list
    "zeek-agent"
  )

  if(TARGET osqueryd)
    list(APPEND target_name_list "zeek-agent-osquery")
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(add_executable_options MACOSX_BUNDLE)
  endif()

  foreach(target_name ${target_name_list})
    add_executable("${target_name}" ${add_executable_options}
      src/main.cpp

      src/zeekagent.h
      src/zeekagent.cpp

      src/zeekconnection.h
      src/zeekconnection.cpp

      src/uniquexxh64state.h
      src/uniquexxh64state.cpp

      src/logger.h
      src/logger.cpp

      src/configuration.h
      src/configuration.cpp

      src/queryscheduler.h
      src/queryscheduler.cpp
    )

    target_link_libraries("${target_name}" PRIVATE
      zeek_agent_cxx_settings
      zeek_logger
      zeek_service_manager
      zeek_database
      zeek_configuration
      zeek_tables

      thirdparty_broker
      thirdparty_xxhash
    )

    target_include_directories("${target_name}" PRIVATE
      src
    )

    if("${target_name}" STREQUAL "zeek-agent-osquery")
      target_compile_definitions("${target_name}" PRIVATE
        ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT
      )

      target_link_libraries("${target_name}" PRIVATE
        zeek_osquery_interface
      )
    endif()

    codeSign("${PROJECT_NAME}" "${CMAKE_CURRENT_SOURCE_DIR}/entitlements.plist")
  endforeach()

  if(ZEEK_AGENT_ENABLE_INSTALL)
    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
      set(destination_path "bin")

    elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
      set(destination_path "/Applications")

    else()
      message(FATAL_ERROR "Unsupported platform")
    endif()

    install(TARGETS ${target_name_list} DESTINATION "${destination_path}")
  endif()

  if(ZEEK_AGENT_ENABLE_DOCUMENTATION)
    add_subdirectory("documentation")
  endif()

  generateZeekAgentTest(
    SOURCE_TARGET
      "zeek-agent"

    SOURCES
      tests/main.cpp

      tests/zeekconnection.cpp
  )
endfunction()

configureCcache()
zeekAgent()
