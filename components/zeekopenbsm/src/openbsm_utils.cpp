#include "openbsm_utils.h"

namespace zeek {

Status getIpFromToken(const au_socketinet_ex32_t &sock, std::string &ip_addr) {
  char ip_str[INET6_ADDRSTRLEN] = {0};
  if (sock.family == 2) {
    struct in_addr ipv4 {};
    ipv4.s_addr = static_cast<in_addr_t>(*sock.addr);
    ip_addr = inet_ntop(AF_INET, &ipv4, ip_str, INET6_ADDRSTRLEN);
    return Status::success();
  } else if (sock.family == 26) {
    struct in6_addr ipv6 {};
    memcpy(&ipv6, sock.addr, sizeof(ipv6));
    ip_addr = inet_ntop(AF_INET6, &ipv6, ip_str, INET6_ADDRSTRLEN);
    return Status::success();
  }
  return Status::failure("Cannot parse IP address from given token due to "
                         "unhandled socket family");
}

Status getPathFromPid(int pid, std::string &path) {
  char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};

  int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret > 0) {
    path = pathbuf;
    return Status::success();
  }
  return Status::failure("Cannot get path from pid: " +
                         std::string(strerror(errno)));
}
} // namespace zeek
