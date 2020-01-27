cmake_minimum_required(VERSION 3.14)
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

set(CPACK_DEBIAN_PACKAGE_RELEASE "${PACKAGE_VERSION}")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_SECTION "default")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>=2.12)")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "${CPACK_PACKAGE_HOMEPAGE_URL}")

set(CPACK_RPM_PACKAGE_RELEASE_DIST "${PACKAGE_VERSION}")
set(CPACK_RPM_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION_SUMMARY}")
set(CPACK_RPM_PACKAGE_GROUP "default")
set(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.12")

function(zeekAgentPackaging)
  if("${ZEEK_AGENT_INSTALL_PATH}" STREQUAL "")
    message(FATAL_ERROR "The ZEEK_AGENT_INSTALL_PATH parameter is mandatory")
  endif()

  set(standalone_zeek_agent_path "${ZEEK_AGENT_INSTALL_PATH}/${CMAKE_INSTALL_PREFIX}/bin/zeek-agent")
  if(EXISTS "${standalone_zeek_agent_path}")
    message(STATUS "Found: Zeek Agent (standalone edition)")
    list(APPEND executable_file_list "${standalone_zeek_agent_path}")
  endif()

  set(osquery_zeek_agent_path "${ZEEK_AGENT_INSTALL_PATH}/${CMAKE_INSTALL_PREFIX}/bin/zeek-agent-osquery")
  if(EXISTS "${osquery_zeek_agent_path}")
    message(STATUS "Found: Zeek Agent (osquery edition)")
    list(APPEND executable_file_list "${osquery_zeek_agent_path}")
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

  install(
    FILES ${executable_file_list}

    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                GROUP_READ GROUP_WRITE GROUP_EXECUTE
                WORLD_READ             WORLD_EXECUTE

    DESTINATION "bin"
  )
endfunction()

set(CPACK_GENERATOR "TGZ")

unset(rpm_executable_path CACHE)
find_program(rpm_executable_path "rpm")
if("${rpm_executable_path}" STREQUAL "rpm_executable_path-NOTFOUND")
  message(WARNING "zeek-agent: The RPM package generator requires the 'rpm' tool")
else()
  list(APPEND CPACK_GENERATOR "RPM")
  message(STATUS "zeek-agent: The RPM generator has been enabled")
endif()

unset(dpkg_executable_path CACHE)
find_program(dpkg_executable_path "dpkg")
if("${dpkg_executable_path}" STREQUAL "dpkg_executable_path-NOTFOUND")
  message(WARNING "zeek-agent: The DEB package generator requires the 'dpkg' tool")
else()
  list(APPEND CPACK_GENERATOR "DEB")
  message(STATUS "zeek-agent: The DEB generator has been enabled")
endif()

include(CPack)

zeekAgentPackaging()
