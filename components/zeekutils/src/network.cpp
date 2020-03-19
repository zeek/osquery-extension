#include <zeek/network.h>

namespace zeek {
#if defined(WIN32)
int poll(struct pollfd fds[], nfds_t nfds, int timeout) {
  return WSAPoll(fds, nfds, timeout);
}
#endif
} // namespace zeek
