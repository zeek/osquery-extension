#!/usr/bin/env bash

export CMAKE_VERSION="3.16.3"
export OSQUERY_VERSION="4.1.1"
export OSQUERY_TOOLCHAIN_VERSION="1.0.0"

main() {
  if [[ $# -ne 2 ]] ; then
    printUsage
    return 1
  fi

  if [[ "$1" != "--zeek-version" ]] ; then
    printf "Invalid parameter specified: ${1}\n"
    printUsage
    return 1
  fi

  local zeek_version="$2"
  if [[ "${zeek_version}" != "3.0" && "${zeek_version}" != "3.1" ]] ; then
    printf "Invalid zeek version specified: ${zeek_version}\n"
    printUsage
    return 1
  fi

  if [ ! -d "build" ] ; then
    executeCommand \
      "Creating the build folder" \
      . \
      mkdir "build"
  fi

  if [ ! -d "package" ] ; then
    executeCommand \
      "Creating the package build folder" \
      . \
      mkdir "package"
  fi

  if [ ! -d "build/ccache" ] ; then
    executeCommand \
      "Creating the ccache folder" \
      . \
      mkdir "build/ccache"
  fi

  if [ ! -d "build/downloads" ] ; then
    executeCommand \
      "Creating the downloads folder" \
      . \
      mkdir "build/downloads"
  fi

  if [ ! -d "build/install" ] ; then
    executeCommand \
      "Creating the install folder" \
      . \
      mkdir "build/install"
  fi

  executeCommand \
    "Updating the system repositories" \
    . \
    sudo apt-get update

  executeCommand \
    "Installing system dependencies" \
    . \
    sudo apt-get install cppcheck ccache curl flex bison rpm doxygen ninja-build graphviz -y

  executeCommand \
    "Synchronizing the submodules" \
    . \
    git submodule sync --recursive

  executeCommand \
    "Fetching the submodules" \
    . \
    git submodule update --init --recursive

  local cmake_release_name="cmake-${CMAKE_VERSION}-Linux-x86_64"
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

  local osquery_toolchain_url="https://github.com/osquery/osquery-toolchain/releases/download/${OSQUERY_TOOLCHAIN_VERSION}/osquery-toolchain-${OSQUERY_TOOLCHAIN_VERSION}.tar.xz"
  local osquery_toolchain_tarball_path="$(realpath build/downloads)/osquery-toolchain-${OSQUERY_TOOLCHAIN_VERSION}.tar.xz"
  local osquery_toolchain_install_path="$(realpath build)/osquery-toolchain"

  if [ ! -d "${osquery_toolchain_install_path}" ] ; then
    if [ ! -f "${osquery_toolchain_tarball_path}" ] ; then
      executeCommand \
        "Downloading the osquery toolchain" \
        . \
        curl -L "${osquery_toolchain_url}" -o "${osquery_toolchain_tarball_path}"

    else
      printf " > Using cached osquery toolchain tarball: ${osquery_toolchain_tarball_path}\n"
    fi

    executeCommand \
      "Extracting the osquery toolchain" \
      "build" \
      tar xf "${osquery_toolchain_tarball_path}"

  else
    printf " > Using cached osquery toolchain directory: ${osquery_toolchain_install_path}\n"
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

  executeCommand \
    "Configuring the project (portable-osquery)" \
    "build" \
    cmake -DOSQUERY_TOOLCHAIN_SYSROOT="${osquery_toolchain_install_path}" -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_ZEEK_COMPATIBILITY:STRING="${zeek_version}" -DZEEK_AGENT_ENABLE_DOCUMENTATION:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=false -G Ninja ../osquery

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

executeCommand() {
  local message="$1"
  printf "\n\n > ${message}\n\n\n"

  local working_directory="$2"

  ( cd "${working_directory}" && ${@:3} )
  if [[ $? -ne 0 ]] ; then
    printf " ! The following step has failed: ${message}\n"
    exit 1
  fi
}

printUsage() {
  printf "Usage:\n\tbuild_release.sh --zeek-version [3.0|3.1]\n\n"
}

main $@
exit $?
