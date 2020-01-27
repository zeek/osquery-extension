if(DEFINED ENV{DESTDIR})
  set(install_destination "$ENV{DESTDIR}/")
endif()

set(install_destination "${install_destination}/${CMAKE_INSTALL_PREFIX}")

if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/external/extension_zeek-agent")
  set(documentation_folder_prefix "external/extension_zeek-agent/")
endif()

set(documentation_folder "${CMAKE_CURRENT_BINARY_DIR}/${documentation_folder_prefix}documentation/html")
if(NOT EXISTS "${documentation_folder}/index.html")
  message(WARNING "zeek-agent: Not installing the Doxygen documentation (was not built)")

else()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${install_destination}/share/doc"
    COMMAND "${CMAKE_COMMAND}" -E copy_directory "${documentation_folder}" "${install_destination}/share/doc/zeek-agent"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
  )
endif()
