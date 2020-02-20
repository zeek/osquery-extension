#pragma once

#include <string>
#include <zeek/status.h>

namespace zeek {
/// \brief Returns the host UUID
Status getHostUUID(std::string &uuid);
} // namespace zeek
