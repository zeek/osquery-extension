#include "osversion.h"

#include <fstream>
#include <sstream>

namespace zeek {
Status getSystemVersion(std::string &version) {
  const std::string kReleaseFile{"/etc/os-release"};
  const std::string kPrettyNameKey{"PRETTY_NAME"};

  version = {};

  std::string os_release;

  {
    std::fstream release_file{kReleaseFile, std::ios::in};
    if (!release_file) {
      return Status::failure("Failed to open the os-release file: " +
                             kReleaseFile);
    }

    std::stringstream stream;
    stream << release_file.rdbuf();

    os_release = stream.str();
  }

  auto pretty_name_index = os_release.find(kPrettyNameKey);
  if (pretty_name_index == std::string::npos) {
    return Status::failure("Failed to locate the " + kPrettyNameKey +
                           " key in the os-release file");
  }

  pretty_name_index += kPrettyNameKey.size() + 2U;
  if (pretty_name_index >= os_release.size()) {
    return Status::failure("Invalid key-value syntax in the os-release file");
  }

  auto pretty_name_last_index = os_release.find("\"", pretty_name_index);
  if (pretty_name_last_index == std::string::npos) {
    return Status::failure("Invalid key-value syntax in the os-release file");
  }

  auto pretty_name_length = pretty_name_last_index - pretty_name_index;
  version.assign(os_release.data() + pretty_name_index, pretty_name_length);

  return Status::success();
}
} // namespace zeek
