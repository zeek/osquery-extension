#!/usr/bin/env bash

buildZeekAgent() {
  executeCommand \
    "Synchronizing the submodules" \
    . \
    git submodule sync --recursive

  executeCommand \
    "Fetching the submodules" \
    . \
    git submodule update --init --recursive

  local cmake_release_name="cmake-${CMAKE_VERSION}-$(uname)-x86_64"
  local cmake_url="https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${cmake_release_name}.tar.gz"
  local cmake_tarball_path="$(realpath build/downloads)/${cmake_release_name}.tar.gz"
  local cmake_install_path="$(realpath build)/${cmake_release_name}"

  if [ ! -d "${cmake_install_path}" ] ; then
    if [ ! -f "${cmake_tarball_path}" ] ; then
      executeCommand \
        "Downloading CMake" \
        . \
        curl -L "${cmake_url}" -o "${cmake_tarball_path}"

    else
      printf " > Using cached CMake tarball: ${cmake_tarball_path}\n"
    fi

    executeCommand \
      "Extracting CMake" \
      "build" \
      tar xzf "${cmake_tarball_path}"

  else
    printf " > Using cached CMake install directory: ${cmake_install_path}\n"
  fi

  if [ -d "osquery" ] ; then
    printf " i Using existing osquery folder\n"

  else
    executeCommand \
      "Downloading the osquery source code for version ${OSQUERY_VERSION}" \
      . \
      git clone --branch "${OSQUERY_VERSION}" https://github.com/osquery/osquery
  fi

  if [ ! -d "$(realpath osquery)/external/extension_zeek-agent" ] ; then
    executeCommand \
      "Linking the Zeek agent source folder to osquery/external" \
      . \
      ln -s "$(pwd)" "$(realpath osquery)/external/extension_zeek-agent"
  fi

  local ccache_folder="$(realpath build/ccache)"
  local install_prefix="/usr"
  local install_destination="$(realpath build/install)"

  export CCACHE_DIR="${ccache_folder}"
  export PATH="${cmake_install_path}/bin:${PATH}"

  if [ ! -z "${osquery_toolchain_sysroot}" ] ; then
    local osquery_toolchain_cmake_param="-DOSQUERY_TOOLCHAIN_SYSROOT:PATH=${osquery_toolchain_sysroot}"
  fi

  if [ ! -z "${signing_identity}" ] ; then
    local signing_identity_cmake_param="-DZEEK_AGENT_CODESIGN_IDENTITY=${signing_identity}"
  fi

  executeCommand \
    "Configuring the project" \
    "build" \
    cmake ${osquery_toolchain_cmake_param} ${signing_identity_cmake_param} -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_ZEEK_COMPATIBILITY:STRING="${zeek_version}" -DZEEK_AGENT_ENABLE_DOCUMENTATION:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=false -G Ninja ../osquery

  executeCommand \
    "Building the project" \
    "build" \
    cmake --build . -- -v

  executeCommand \
    "Running the tests" \
    "build" \
    cmake --build . --target zeek_agent_tests -- -v

  executeCommand \
    "Generating the Doxygen documentation" \
    "build" \
    cmake --build . --target doxygen -- -v

  export DESTDIR="${install_destination}"

  executeCommand \
    "Running the install target" \
    "build" \
    cmake --build . --target install -- -v 

  executeCommand \
    "Configuring the packaging project" \
    "package" \
    cmake -G Ninja -DZEEK_AGENT_ZEEK_COMPATIBILITY:STRING="${zeek_version}" -DZEEK_AGENT_INSTALL_PATH:PATH="${install_destination}" -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" ../packaging

  executeCommand \
    "Generating packages" \
    "package" \
    cmake --build . --target package -- -v

  printf "\n\nDone! Packages are located in the 'package' folder\n"
  return 0
}

