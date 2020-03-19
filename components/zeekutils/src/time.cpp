#include <ctime>

#include <zeek/time.h>

namespace zeek {
#if defined(__linux__) || defined(__APPLE__)
void getLocalTime(const time_t *timep, struct tm *result) {
  localtime_r(timep, result);
}

#elif defined(WIN32)
void getLocalTime(const time_t *timep, struct tm *result) {
  localtime_s(result, timep);
}

#else
#error Unsupported platform
#endif
} // namespace zeek
