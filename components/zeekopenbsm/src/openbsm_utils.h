#pragma once

#include <arpa/inet.h>
#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <string>

namespace zeek {
/// \brief Extract ip address from openbsm audit token
/// \param tok openbsm audit token
/// \return output ip address string
std::string getIpFromToken(const tokenstr_t &tok);

/// \brief Get process path from given pid
/// \param pid process pid
/// \return process path string
std::string getPathFromPid(int pid);
} // namespace zeek
