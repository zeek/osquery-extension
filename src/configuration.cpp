#include "configuration.h"

#include <filesystem>
#include <iostream>

#ifdef WIN32
#include <Windows.h>
#endif

namespace zeek {
namespace {
IZeekConfiguration::Ref zeek_config;
} // namespace

std::string getConfigurationFilePath() {
#ifdef WIN32
  std::string executable_path;

  {
    std::vector<TCHAR> buffer(8192, 0);
    auto char_count = static_cast<DWORD>(buffer.size() / 2) - 1;

    if (GetModuleFileName(nullptr, buffer.data(), char_count) == 0 ||
        GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      std::cerr << "Failed to determine the executable path. The config will "
                   "be loaded from the working directory\n";
      return std::string("config.json");
    }

    executable_path = buffer.data();
  }

#ifdef UNICODE
  std::vector<char> temp_buffer(0, executable_path.size() * 4);

  auto char_count = WideCharToMultiByte(CP_UTF8, 0, executable_path.c_str(), -1,
                                        temp_buffer.data(), temp_buffer.size(),
                                        nullptr, nullptr);
  executable_path = temp_buffer.data();
#endif

  auto config_path =
      std::filesystem::path(executable_path).parent_path().parent_path() /
      "etc" / "config.json";
  return config_path.string();

#else
  const std::string kConfigurationFilePath{"/etc/zeek-agent/config.json"};
  return kConfigurationFilePath;
#endif
}

Status initializeConfiguration(IVirtualDatabase &virtual_database) {
  auto configuration_path = getConfigurationFilePath();
  auto status = IZeekConfiguration::create(zeek_config, virtual_database,
                                           configuration_path);

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

void deinitializeConfiguration() { zeek_config.reset(); }

IZeekConfiguration &getConfig() { return *zeek_config.get(); }
} // namespace zeek
