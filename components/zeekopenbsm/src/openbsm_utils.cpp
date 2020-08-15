#include "openbsm_utils.h"

namespace zeek {

std::string getIpFromToken(const tokenstr_t &tok) {
  char ip_str[INET6_ADDRSTRLEN] = {0};
  if (tok.tt.sockinet_ex32.family == 2) {
    struct in_addr ipv4 {};
    ipv4.s_addr = static_cast<in_addr_t>(*tok.tt.sockinet_ex32.addr);
    return std::string(inet_ntop(AF_INET, &ipv4, ip_str, INET6_ADDRSTRLEN));
  } else {
    struct in6_addr ipv6 {};
    memcpy(&ipv6, tok.tt.sockinet_ex32.addr, sizeof(ipv6));
    return std::string(inet_ntop(AF_INET6, &ipv6, ip_str, INET6_ADDRSTRLEN));
  }
}

std::string getPathFromPid(int pid) {
  char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};

  int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret > 0) {
    return std::string(pathbuf);
  } else {
    return "";
  }
}
} // namespace zeek
