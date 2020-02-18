#!/usr/bin/env bash

if [ ! -f './scripts/posix/common.sh' ] ; then
  printf "Please launch this script from the source directory: ./scripts/build_linux_release.sh\n"
  exit 1
fi

source ./scripts/posix/common.sh
source ./scripts/posix/build.sh

export CMAKE_VERSION="3.16.3"
export OSQUERY_VERSION="4.1.1"
export OSQUERY_TOOLCHAIN_VERSION="1.0.0"

main() {
  executeCommand \
    "Installing system dependencies" \
    . \
    sudo apt-get install cppcheck ccache curl flex bison rpm doxygen ninja-build graphviz -y

  local osquery_toolchain_url="https://github.com/osquery/osquery-toolchain/releases/download/${OSQUERY_TOOLCHAIN_VERSION}/osquery-toolchain-${OSQUERY_TOOLCHAIN_VERSION}.tar.xz"
  local osquery_toolchain_tarball_path="$(realpath build/downloads)/osquery-toolchain-${OSQUERY_TOOLCHAIN_VERSION}.tar.xz"
  local osquery_toolchain_sysroot="$(realpath build)/osquery-toolchain"

  if [ ! -d "${osquery_toolchain_sysroot}" ] ; then
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
    printf " > Using cached osquery toolchain directory: ${osquery_toolchain_sysroot}\n"
  fi

  buildZeekAgent
  return $?
}

main $@
exit $?

