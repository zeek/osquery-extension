#include "osversion.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>

namespace zeek {
Status getSystemVersion(std::string &version) {
  version = {};

  static const auto kWindowsVersionKey =
      _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  static const auto kProductNameValueName = _T("ProductName");

  DWORD value_size{0};
  if (RegGetValue(HKEY_LOCAL_MACHINE, kWindowsVersionKey, kProductNameValueName,
                  RRF_RT_REG_SZ, nullptr, nullptr,
                  &value_size) != ERROR_SUCCESS) {
    return Status::failure("Failed to access the key");
  }

  version.resize(static_cast<std::size_t>(value_size));
  if (RegGetValue(HKEY_LOCAL_MACHINE, kWindowsVersionKey, kProductNameValueName,
                  RRF_RT_REG_SZ, nullptr, &version[0],
                  &value_size) != ERROR_SUCCESS) {
    return Status::failure("Failed to read the key");
  }

  return Status::success();
}
} // namespace zeek
