#pragma once

/* #undef BROKER_HAVE_ROCKSDB */

/* #undef BROKER_APPLE */
/* #undef BROKER_FREEBSD */
#define BROKER_LINUX

// GCC uses __SANITIZE_ADDRESS__, Clang uses __has_feature
#if defined(__SANITIZE_ADDRESS__)
    #define BROKER_ASAN
#endif

#if defined(__has_feature)
    #if __has_feature(address_sanitizer)
        #define BROKER_ASAN
    #endif
#endif

#if defined(BROKER_ASAN)
    #include <sanitizer/lsan_interface.h>
    #define BROKER_LSAN_CHECK(x) __lsan_do_leak_check(x)
    #define BROKER_LSAN_ENABLE(x) __lsan_enable(x)
    #define BROKER_LSAN_DISABLE(x) __lsan_disable(x)
    #define BROKER_LSAN_IGNORE(x) __lsan_ignore_object(x)
#else
    #define BROKER_LSAN_CHECK(x)
    #define BROKER_LSAN_ENABLE(x)
    #define BROKER_LSAN_DISABLE(x)
    #define BROKER_LSAN_IGNORE(x)
#endif