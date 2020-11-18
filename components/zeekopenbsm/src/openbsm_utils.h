#pragma once

#include <arpa/inet.h>
#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <string>
#include <zeek/status.h>

namespace zeek {
/// \brief Extract ip address from openbsm audit token
/// \param tok openbsm audit token
/// \return output ip address string
Status getIpFromToken(const au_socketinet_ex32_t &sock, std::string &ip_addr);

/// \brief Get process path from given pid
/// \param pid process pid
/// \return process path string
Status getPathFromPid(int pid, std::string &path);
} // namespace zeek
