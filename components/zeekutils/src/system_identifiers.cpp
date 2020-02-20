#include <zeek/system_identifiers.h>

#include <vector>

#if defined(__linux__)
#include <fstream>
#include <unistd.h>

#elif defined(__APPLE__)
#include <unistd.h>
#include <uuid/uuid.h>

#else
#error Unsupported platform
#endif

namespace zeek {
namespace {
// 16-bytes + 4 separators
const std::size_t kExpectedCharacterCount{36U};

// Empty UUID
const std::string kNullUUID{"00000000-0000-0000-0000-000000000000"};
} // namespace

Status getHostUUID(std::string &uuid) {
  uuid = {};

  std::string uuid_value;

#if defined(__linux__)
  const std::string kHostUUIDLocation{"/sys/class/dmi/id/product_uuid"};

  std::fstream uuid_file{kHostUUIDLocation, std::ios::in};
  if (!uuid_file) {
    return Status::failure("Failed to open the UUID definition file: " +
                           kHostUUIDLocation);
  }

  std::getline(uuid_file, uuid_value);

#elif defined(__APPLE__)
  uuid_t raw_uuid_value{};
  timespec w{5, 0};
  if (gethostuuid(raw_uuid_value, &w) != 0) {
    return Status::failure(
        "Failed to acquire the host identifier; gethostuuid() has failed");
  }

  std::string buffer(kExpectedCharacterCount + 1, '\0');
  uuid_unparse(raw_uuid_value, &buffer[0]);

  uuid_value = buffer.c_str();

#else
#error Unsupported platform
#endif

  if (uuid_value.empty() || uuid_value == kNullUUID ||
      uuid_value.size() != kExpectedCharacterCount) {

    return Status::failure("Invalid UUID generated");
  }

  uuid = std::move(uuid_value);
  return Status::success();
}

std::string getSystemHostname() {
#if defined(__linux__) || defined(__APPLE__)
  std::vector<char> buffer(1024);
  gethostname(buffer.data(), buffer.size());
  buffer.push_back(0);

  return buffer.data();
#else
#error Unsupported platform
#endif
}
} // namespace zeek
