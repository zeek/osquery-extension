#!/usr/bin/env bash

if [ ! -f './scripts/posix/common.sh' ] ; then
  printf "Please launch this script from the source directory: ./scripts/build_macos_release.sh\n"
  exit 1
fi

source ./scripts/posix/common.sh
source ./scripts/posix/build.sh

export CMAKE_VERSION="3.16.3"
export OSQUERY_VERSION="4.1.1"

main() {
  executeCommand \
    "Installing system dependencies" \
    . \
    brew install cppcheck ccache flex bison doxygen ninja graphviz coreutils

  buildZeekAgent
  return $?
}

main $@
exit $?

