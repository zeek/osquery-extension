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
    /MT
    /WX
    /W4
    /bigobj
  )
endif()
