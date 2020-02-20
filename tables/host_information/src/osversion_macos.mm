#include "osversion.h"

#include <sstream>

#include <Foundation/NSProcessInfo.h>

namespace zeek {
Status getSystemVersion(std::string &version) {
  version = {};

  auto version_struct = [[NSProcessInfo processInfo] operatingSystemVersion];

  std::stringstream buffer;
  buffer << version_struct.majorVersion << "." << version_struct.minorVersion
         << "." << version_struct.patchVersion;

  version = buffer.str();
  return Status::success();
}
}
