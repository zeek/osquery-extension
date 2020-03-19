cmake_minimum_required(VERSION 3.16.3)
project("zeek-agent-documentation")

function(zeekAgentDocumentation)
  set(source_folder_list
    "components"
    "src"
  )
  
  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(optional_hints
      HINTS
        "$ENV{PROGRAMFILES}\\doxygen\\bin"
        "$ENV{PROGRAMFILES\(X86\)}\\doxygen\\bin"
    )

    message(WARNING "HINTS: ${optional_hints}")

    set(executable_extension ".exe")
  endif()

  find_program(
    doxygen_executable_path
    "doxygen${executable_extension}"
    ${optional_hints}
  )

  if("${doxygen_executable_path}" STREQUAL "doxygen_executable_path-NOTFOUND")
    message(FATAL_ERROR "zeek-agent: The Doxygen command was not found")
  endif()

  # We may be located inside the osquery source tree; use a relative path
  # for the INPUT field
  set(zeek_agent_root "${CMAKE_CURRENT_SOURCE_DIR}/..")

  foreach(source_folder ${source_folder_list})
    set(ZEEK_AGENT_DOCUMENTATION_SOURCE_PATH "${ZEEK_AGENT_DOCUMENTATION_SOURCE_PATH} ${zeek_agent_root}/${source_folder}")
  endforeach()

  configure_file(
    "doxygen.conf.inc"
    "${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf"
    @ONLY
  )

  add_custom_target(doxygen
    COMMAND doxygen "${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf"
    COMMENT "zeek-agent: Generating Doxygen documentation..."
    VERBATIM
  )

  if(ZEEK_AGENT_ENABLE_INSTALL)
    install(SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/install.cmake")
  endif()
endfunction()

zeekAgentDocumentation()
