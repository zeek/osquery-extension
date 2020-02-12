cmake_minimum_required(VERSION 3.16.3)

function(codeSign target_name entitlements_file)
  if(NOT TARGET "${target_name}")
    message(FATAL_ERROR "Invalid target name specified")
  endif()

  get_target_property(target_type "${target_name}" TYPE)
  if("${target_type}" STREQUAL "target_type-NOTFOUND" OR
     NOT "${target_type}" STREQUAL "EXECUTABLE")

    message(FATAL_ERROR "The specified target is not an executable")
  endif()

  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    return()
  endif()

  get_target_property(target_type "${target_name}" MACOSX_BUNDLE)
  if(NOT target_type)
    message(FATAL_ERROR "The specified target is not configured as a macOS bundle")
  endif()

  if(NOT EXISTS "${entitlements_file}")
    message(FATAL_ERROR "Invalid path to entitlements file")
  endif()

  if("${ZEEK_AGENT_CODESIGN_IDENTITY}" STREQUAL "")
    message(WARNING "No codesign identity selected. Skipping code signing")
    return()
  endif()

  get_target_property(target_binary_dir "${target_name}" BINARY_DIR)
  if("${target_binary_dir}" STREQUAL "target_binary_dir-NOTFOUND")
    message(FATAL_ERROR "Failed to determine the binary directory for the specified target")
  endif()

  set(target_file_path "${target_binary_dir}/${target_name}.app")

  add_custom_command(
    TARGET "${target_name}" POST_BUILD
    COMMAND codesign --entitlements "${entitlements_file}" --force -s "${ZEEK_AGENT_CODESIGN_IDENTITY}" -v "${target_file_path}"
    COMMENT "Codesigning target ${target_name}..."
    VERBATIM
  )
endfunction()

