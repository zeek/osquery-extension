cmake_minimum_required(VERSION 3.16.3)
project("zeek-agent")

include("../cmake/version.cmake")

set(ZEEK_AGENT_INSTALL_PATH "" CACHE STRING "This is the path where the Zeek Agent has been installed")
set(PACKAGE_VERSION 1)

string(REPLACE "." ";" ZEEK_AGENT_VERSION_COMPONENTS "${ZEEK_AGENT_VERSION}")
list(GET ZEEK_AGENT_VERSION_COMPONENTS 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET ZEEK_AGENT_VERSION_COMPONENTS 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET ZEEK_AGENT_VERSION_COMPONENTS 2 CPACK_PACKAGE_VERSION_PATCH)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Zeek Agent is an endpoint monitoring tool that reports system events and data to a Zeek server instance.")
set(CPACK_PACKAGE_NAME "zeek-agent")
set(CPACK_PACKAGE_VENDOR "Zeek")
set(CPACK_PACKAGE_CONTACT "lt@zeek.org")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://zeek.org")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${ZEEK_AGENT_VERSION}-${PACKAGE_VERSION}.x86_64")
set(CPACK_PACKAGE_RELOCATABLE ON)
set(CPACK_SET_DESTDIR ON)

set(CPACK_GENERATOR "TGZ")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
  include("cmake/linux.cmake")
endif()

function(zeekAgentPackaging)
  if("${ZEEK_AGENT_INSTALL_PATH}" STREQUAL "")
    message(FATAL_ERROR "The ZEEK_AGENT_INSTALL_PATH parameter is mandatory")
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(prefix_folder_name "${CMAKE_INSTALL_PREFIX}/bin")
    set(application_name_suffix "")

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(prefix_folder_name "Applications")
    set(application_name_suffix ".app")

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  message(STATUS "Looking for executables inside ${ZEEK_AGENT_INSTALL_PATH}...")

  set(standalone_zeek_agent_path "${ZEEK_AGENT_INSTALL_PATH}/${prefix_folder_name}/zeek-agent${application_name_suffix}")
  if(EXISTS "${standalone_zeek_agent_path}")
    message(STATUS "Found: Zeek Agent (standalone edition)")
    list(APPEND executable_file_list "${standalone_zeek_agent_path}")
  else()
    message(WARNING "Not found: ${standalone_zeek_agent_path}")
  endif()

  set(osquery_zeek_agent_path "${ZEEK_AGENT_INSTALL_PATH}/${prefix_folder_name}/zeek-agent-osquery${application_name_suffix}")
  if(EXISTS "${osquery_zeek_agent_path}")
    message(STATUS "Found: Zeek Agent (osquery edition)")
    list(APPEND executable_file_list "${osquery_zeek_agent_path}")
  else()
    message(WARNING "Not found: ${osquery_zeek_agent_path}")
  endif()

  if("${executable_file_list}" STREQUAL "")
    message(FATAL_ERROR "The specified ZEEK_AGENT_INSTALL_PATH value is not valid")
  endif()

  set(documentation_path "${ZEEK_AGENT_INSTALL_PATH}/${CMAKE_INSTALL_PREFIX}/share/doc/zeek-agent")
  if(EXISTS "${documentation_path}/index.html")
    message(STATUS "Found: Zeek Agent documentation")

    install(
      DIRECTORY "${documentation_path}"
      DESTINATION "share/doc"
    )
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(install_directive "FILES")

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(install_directive "DIRECTORY")

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    install(
      FILES ${executable_file_list}

      PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                  GROUP_READ GROUP_WRITE GROUP_EXECUTE
                  WORLD_READ             WORLD_EXECUTE

      DESTINATION "bin"
    )

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    install(
      DIRECTORY ${executable_file_list}
      DESTINATION "/Applications"
      USE_SOURCE_PERMISSIONS
    )

  else()
    message(FATAL_ERROR "Unsupported platform")
  endif()

  set(sample_config_list
    "config/config.sample.json"
  )

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    list(APPEND sample_config_list
      "config/10-zeek_agent.sample.rules"
    )
  endif()

  install(
    FILES ${sample_config_list}
    DESTINATION "/etc/zeek-agent"
  )

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set(service_definition "${CMAKE_CURRENT_BINARY_DIR}/zeek-agent.service")

    configure_file(
      "${CMAKE_CURRENT_SOURCE_DIR}/config/zeek-agent.service.inc"
      "${service_definition}"
    )

    install(
      FILES "${service_definition}"
      DESTINATION "lib/systemd/system"
    )
  endif()
endfunction()

include(CPack)
zeekAgentPackaging()
