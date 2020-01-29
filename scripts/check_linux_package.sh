#!/usr/bin/env bash

main() {
  if [ $# -ne 1 ] ; then
    printUsage
    return 1
  fi

  local targz_package_path="$(realpath $1)"
  if [ ! -f "${targz_package_path}" ] ; then
    printf "The given package path is not valid\n\n"

    printUsage
    return 1
  fi

  local temporary_folder="$(mktemp -d)"
  ( cd "${temporary_folder}" && tar xzf "${targz_package_path}" --strip-components=1 )
  if [ $? -ne 0 ] ; then
    printf "Failed to extract the tar.gz package\n"
    return 1
  fi

  printf "Checking the package file list\n\n"
  declare -a expected_file_list=( "${temporary_folder}/usr/bin/zeek-agent" "${temporary_folder}/usr/bin/zeek-agent-osquery" "${temporary_folder}/usr/share/doc/zeek-agent/index.html" )

  for expected_path in "${expected_file_list[@]}" ; do
    if [ ! -f "${expected_path}" ] ; then
      printf " x ${expected_path}\n"
      return 1
    fi

    local is_elf_binary=`file "${expected_path}" | grep ELF | wc -l`
    if [ ${is_elf_binary} -eq 1 ] ; then
      local dependency_count=`ldd -d "${expected_path}" | wc -l`
      if [ ${dependency_count} -ne 7 ] ; then
        printf " x ${expected_path}\n\n"

        printf "The binary dependencies do not look right!\n"
        ldd -d "${expected_path}"
        return 1
      fi

      if [[ "${expected_path}" == *"zeek-agent-osquery"* ]] ; then
        export ASAN_OPTIONS=detect_container_overflow=0
      else
        unset ASAN_OPTIONS
      fi

      local binary_output=`"${expected_path}" 2> /dev/null`
      local string_found=`echo ${binary_output} | grep 'Zeek Agent v' | wc -l`
      if [ ${string_found} -ne 1 ] ; then
        printf " x ${expected_path}\n\n"

        printf "The binary could not be started\n"
        return 1
      fi
    fi

    printf " > ${expected_path}\n"
  done

  printf "\nThe package appears to be correct!\n\n"
  return 0
}

printUsage() {
  printf "Usage:\n\tcheck_linux_package.sh /path/to/package.tar.gz\n\n"
}

main $@
exit $?
