#pragma once

#include <string>
#include <vector>

namespace zeek {
/// \brief Get ip addresses of this host
/// \return A vector of ip addresses strings
std::vector<std::string> getHostIPAddrs();
} // namespace zeek
