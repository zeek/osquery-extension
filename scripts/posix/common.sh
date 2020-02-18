#!/usr/bin/env bash

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
  printf "Usage: -z [3.0|3.1]"

  if [[ "$(uname)" == "Darwin" ]] ; then
    printf " -s signing-identity"
  fi

  printf "\n"
}

createBuildFolders() {
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
}

# Automatically parse the arguments as soon as this file is sourced
while getopts "z:s:" arg ; do
  case "${arg}" in
    z)
      zeek_version=${OPTARG}
      ;;
    s)
      signing_identity=${OPTARG}
      ;;
    *)
      printUsage
      exit 1
      ;;
   esac
done

if [[ -z "${zeek_version}" ]] ; then
  printUsage
  exit 1
fi

if [[ "$(uname)" == "Darwin" ]] ; then
  if [[ -z "${signing_identity}" ]] ; then
    printf "The signing identity is mandatory for macOS builds\n\n"
    printUsage
    exit 1
  fi

else
  if [[ ! -z "${signing_identity}" ]] ; then
    printf "The signing identity is only supported on macOS\n\n"
    printUsage
    exit 1
  fi
fi

createBuildFolders
