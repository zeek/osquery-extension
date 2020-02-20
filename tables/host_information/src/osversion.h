#pragma once

#include <string>

#include <zeek/status.h>

namespace zeek {
Status getSystemVersion(std::string &version);
}
