#include <zeek/system_identifiers.h>

#include <vector>

#if defined(__linux__)
#include <fstream>
#include <unistd.h>

#elif defined(__APPLE__)
#include <unistd.h>
#include <uuid/uuid.h>

#elif defined(WIN32)
#include <tchar.h>
#include <zeek/network.h>

#else
#error Unsupported platform
#endif
#include <iostream>
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

#elif defined(WIN32)
  static const auto kCryptographyKeyPath =
      _T("SOFTWARE\\Microsoft\\Cryptography");

  static const auto kMachineGuidValueName = _T("MachineGuid");

  DWORD value_size{0};
  if (RegGetValue(HKEY_LOCAL_MACHINE, kCryptographyKeyPath,
                  kMachineGuidValueName, RRF_RT_REG_SZ, nullptr, nullptr,
                  &value_size) != ERROR_SUCCESS) {

    return Status::failure("Failed to access the MachineGuid registry key");
  }

  std::vector<char> buffer(value_size + 1, 0);
  if (RegGetValue(HKEY_LOCAL_MACHINE, kCryptographyKeyPath,
                  kMachineGuidValueName, RRF_RT_REG_SZ, nullptr, buffer.data(),
                  &value_size) != ERROR_SUCCESS) {

    return Status::failure("Failed to read the MachineGuid registry key");
  }

  uuid_value = buffer.data();

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
#if defined(__linux__) || defined(__APPLE__) || defined(WIN32)
  std::vector<char> buffer(1024);
  gethostname(buffer.data(), static_cast<int>(buffer.size()));
  buffer.push_back(0);

  return buffer.data();
#else
#error Unsupported platform
#endif
}
} // namespace zeek
