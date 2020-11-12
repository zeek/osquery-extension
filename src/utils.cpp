#include "utils.h"
#include "logger.h"

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

namespace zeek {
std::vector<std::string> getHostIPAddrs() {
  std::vector<std::string> ip_addrs;

#if defined(__linux__) || defined(__APPLE__)
  ifaddrs *ifaddrs = nullptr;
  if (auto err = getifaddrs(&ifaddrs)) {
    getLogger().logMessage(IZeekLogger::Severity::Error,
                           "Failed to get IP addresses of the host " +
                               std::string(strerror(errno)));
    return {};
  }

  for (auto *ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || (ifa->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      auto addr =
          reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr)->sin_addr;
      char addressBuffer[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &addr, addressBuffer, INET_ADDRSTRLEN);
      ip_addrs.push_back(addressBuffer);
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      auto addr =
          reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr)->sin6_addr;
      char addressBuffer[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &addr, addressBuffer, INET6_ADDRSTRLEN);
      ip_addrs.push_back(addressBuffer);
    }
  }

  freeifaddrs(ifaddrs);
#endif

  return ip_addrs;
}
} // namespace zeek
