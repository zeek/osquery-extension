cmake_minimum_required(VERSION 3.14)
project("openssl")

include(ExternalProject)

function(zeekAgentLibrariesOpenSSL)
  set(openssl_version "1.1.1d")

  get_target_property(zlib_include_path thirdparty_zlib
    INTERFACE_INCLUDE_DIRECTORIES
  )

  if("${zlib_include_path}" STREQUAL "zlib_include_path-NOTFOUND")
    message(FATAL_ERROR "Failed to locate the include directory for zlib")
  endif()

  set(install_directory "${CMAKE_CURRENT_BINARY_DIR}/install")

  if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    ExternalProject_Add(thirdparty_openssl_builder
      DOWNLOAD_DIR
        "${CMAKE_CURRENT_BINARY_DIR}"

      URL
        "https://www.openssl.org/source/openssl-${openssl_version}.tar.gz"

      CONFIGURE_COMMAND 
        "${CMAKE_COMMAND}" -E env CC="${CMAKE_C_COMPILER}" AR="${CMAKE_AR}"
        perl ./Configure linux-x86_64 no-ssl2 no-ssl3 no-asm no-shared no-weak-ssl-ciphers
              zlib-dynamic enable-cms "--with-zlib-include=${zlib_include_path}"
              "--with-zlib-lib=$<TARGET_FILE:thirdparty_zlib>" "--prefix=/"
              "--openssldir=/etc/openssl" -fPIC --sysroot=${CMAKE_SYSROOT}
              -l:libunwind.a -lpthread
      
      BUILD_COMMAND
        make depend &&
        make -j 2

      INSTALL_COMMAND
        make DESTDIR="${install_directory}" install

      BUILD_IN_SOURCE
        true

      DEPENDS
        thirdparty_zlib
    )

    set(lib_folder_name "lib64")

  elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    ExternalProject_Add(thirdparty_openssl_builder
      DOWNLOAD_DIR
        "${CMAKE_CURRENT_BINARY_DIR}"

      URL
        "https://www.openssl.org/source/openssl-${openssl_version}.tar.gz"

      CONFIGURE_COMMAND 
        "${CMAKE_COMMAND}" -E env CC="${CMAKE_C_COMPILER}" AR="${CMAKE_AR}"
        perl ./Configure darwin64-x86_64-cc no-ssl2 no-ssl3 no-asm no-shared no-weak-ssl-ciphers
              zlib-dynamic enable-cms "--with-zlib-include=${zlib_include_path}"
              "--with-zlib-lib=$<TARGET_FILE:thirdparty_zlib>" "--prefix=/"
              "--openssldir=/etc/openssl" -fPIC &&
        /usr/bin/sed -i ".bak" "s+^CFLAGS=+CFLAGS=-isysroot ${CMAKE_OSX_SYSROOT} +g" "Makefile"

      BUILD_COMMAND
        make depend &&
        make -j 2

      INSTALL_COMMAND
        make DESTDIR="${install_directory}" install

      BUILD_IN_SOURCE
        true

      DEPENDS
        thirdparty_zlib
    )

    set(lib_folder_name "lib")

  else()
    message(FATAL_ERROR "Unsupported system")
  endif()

  add_library(thirdparty_openssl_libcrypto STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_openssl_libcrypto PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
      "${install_directory}/include"

    IMPORTED_LOCATION
      "${install_directory}/${lib_folder_name}/libcrypto.a"
  )

  add_dependencies(thirdparty_openssl_libcrypto
    thirdparty_openssl_builder
  )

  add_library(thirdparty_openssl_libssl STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_openssl_libssl PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
      "${install_directory}/include"

    IMPORTED_LOCATION
      "${install_directory}/${lib_folder_name}/libssl.a"
  )

  add_dependencies(thirdparty_openssl_libssl
    thirdparty_openssl_builder
  )

  add_library(thirdparty_openssl INTERFACE)
  target_link_libraries(thirdparty_openssl INTERFACE
    thirdparty_openssl_libcrypto
    thirdparty_openssl_libssl
  )
endfunction()

zeekAgentLibrariesOpenSSL()
