cmake_minimum_required(VERSION 3.16.3)

macro(configureCcache)
  find_program(ccache_executable_path ccache)
  if("${ccache_executable_path}" STREQUAL "ccache_executable_path-NOTFOUND")
    message(STATUS "zeek-agent: ccache is not enabled (not found)")

  else()
    set(CMAKE_C_COMPILER_LAUNCHER "${ccache_executable_path}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${ccache_executable_path}")

    set(configured_cache_path "$ENV{CCACHE_DIR}")
    if("${configured_cache_path}" STREQUAL "")
      set(configured_cache_path "system default")
    endif()

    message(STATUS "zeek-agent: ccache enabled (${configured_cache_path})")
  endif()
endmacro()

