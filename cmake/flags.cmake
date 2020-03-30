cmake_minimum_required(VERSION 3.16.3)

if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  set(ZEEK_AGENT_COMMON_COMPILATION_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wpedantic
    -Wunused
  )

else()
  set(ZEEK_AGENT_COMMON_COMPILATION_FLAGS
    /WX
    /W4
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    list(APPEND ZEEK_AGENT_COMMON_COMPILATION_FLAGS
      /BIGOBJ
    )
  endif()
endif()
