#pragma once

#include <string>
#include <zeek/status.h>

namespace zeek {
/// \brief Returns the host UUID
Status getHostUUID(std::string &uuid);

/// \brief Returns the system hostname
std::string getSystemHostname();
} // namespace zeek
