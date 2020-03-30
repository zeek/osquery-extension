#pragma once

/* #undef BROKER_HAVE_ROCKSDB */

/* #undef BROKER_APPLE */
/* #undef BROKER_FREEBSD */
/* #undef BROKER_LINUX */
/* #undef BROKER_WINDOWS */
/* #undef BROKER_BIG_ENDIAN */
#define BROKER_HAS_STD_FILESYSTEM

#define BROKER_USE_SSE2

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
    #define BROKER_LSAN_ENABLE() __lsan_enable()
    #define BROKER_LSAN_DISABLE() __lsan_disable()
    #define BROKER_LSAN_IGNORE(x) __lsan_ignore_object(x)
#else
    #define BROKER_LSAN_CHECK(x)
    #define BROKER_LSAN_ENABLE()
    #define BROKER_LSAN_DISABLE()
    #define BROKER_LSAN_IGNORE(x)
#endif
