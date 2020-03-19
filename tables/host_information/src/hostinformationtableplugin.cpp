#include "hostinformationtableplugin.h"
#include "osversion.h"

#include <zeek/system_identifiers.h>

#include <broker/version.hh>

#if defined(__linux__) || defined(__APPLE__)
#include <errno.h>
#include <sys/utsname.h>

#elif defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>

#else
#error Unsupported platform
#endif

namespace zeek {
namespace {
#if defined(__linux__) || defined(__APPLE__)
void getOSInformation(HostInformationTablePlugin::Row &row) {
  struct utsname uname_info {};
  if (uname(&uname_info) >= 0) {
    row["os_name"] = uname_info.sysname;
    row["os_version"] = uname_info.version;
    row["os_release"] = uname_info.release;
    row["os_machine"] = uname_info.machine;

  } else {
    row["os_name"] = "";
    row["os_version"] = "";
    row["os_release"] = "";
    row["os_machine"] = "";
  }
}

#elif defined(WIN32)
void getOSInformation(HostInformationTablePlugin::Row &row) {
  row["os_name"] = "Windows";
  row["os_version"] = "";

  SYSTEM_INFO system_info{};
  GetNativeSystemInfo(&system_info);

  switch (system_info.wProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    row["os_machine"] = "AMD64";
    break;

  case PROCESSOR_ARCHITECTURE_ARM:
    row["os_machine"] = "ARM";
    break;

  case PROCESSOR_ARCHITECTURE_ARM64:
    row["os_machine"] = "ARM64";
    break;

  case PROCESSOR_ARCHITECTURE_IA64:
    row["os_machine"] = "IA64";
    break;

  case PROCESSOR_ARCHITECTURE_UNKNOWN:
  default:
    row["os_machine"] = "UNKNOWN";
    break;
  }

  static const auto kWindowsVersionKey =
      _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
  static const auto kReleaseIdValueName = _T("ReleaseId");

  DWORD value_size{0};
  if (RegGetValue(HKEY_LOCAL_MACHINE, kWindowsVersionKey, kReleaseIdValueName,
                  RRF_RT_REG_SZ, nullptr, nullptr,
                  &value_size) != ERROR_SUCCESS) {

    row["os_release"] = "";
    return;
  }

  std::string buffer(static_cast<std::size_t>(value_size), '\0');
  if (RegGetValue(HKEY_LOCAL_MACHINE, kWindowsVersionKey, kReleaseIdValueName,
                  RRF_RT_REG_SZ, nullptr, &buffer[0],
                  &value_size) != ERROR_SUCCESS) {

    row["os_release"] = "";
    return;
  }

  row["os_release"] = std::move(buffer);
}

#else
#error Unsupported platform
#endif
} // namespace

struct HostInformationTablePlugin::PrivateData final {};

HostInformationTablePlugin::~HostInformationTablePlugin() {}

const std::string &HostInformationTablePlugin::name() const {
  static const std::string kTableName{"host_information"};
  return kTableName;
}

const HostInformationTablePlugin::Schema &
HostInformationTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "os_name", IVirtualTable::ColumnType::String },
    { "os_version", IVirtualTable::ColumnType::String },
    { "os_release", IVirtualTable::ColumnType::String },
    { "os_machine", IVirtualTable::ColumnType::String },
    { "system_version", IVirtualTable::ColumnType::String },
    { "hostname", IVirtualTable::ColumnType::String },
    { "osquery_enabled", IVirtualTable::ColumnType::Integer },
    { "uuid", IVirtualTable::ColumnType::String },
    { "broker_version", IVirtualTable::ColumnType::String },
    { "agent_version", IVirtualTable::ColumnType::String }
  };
  // clang-format on

  return kTableSchema;
}

Status HostInformationTablePlugin::generateRowList(RowList &row_list) {
  Row row;
  getOSInformation(row);

  std::string system_version;
  auto status = getSystemVersion(system_version);
  if (!status.succeeded()) {
    row["system_version"] = "";
  } else {
    row["system_version"] = system_version;
  }

  row["hostname"] = getSystemHostname();

#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
  row["osquery_enabled"] = static_cast<std::int64_t>(1);
#else
  row["osquery_enabled"] = static_cast<std::int64_t>(0);
#endif

  std::string uuid;
  status = getHostUUID(uuid);
  if (!status.succeeded()) {
    row["uuid"] = "";
  } else {
    row["uuid"] = std::move(uuid);
  }

  row["broker_version"] = broker::version::string();
  row["agent_version"] = std::string(ZEEK_AGENT_VERSION);

  row_list = {std::move(row)};
  return Status::success();
}

HostInformationTablePlugin::HostInformationTablePlugin() : d(new PrivateData) {}

Status IHostInformationTablePlugin::create(Ref &obj) {
  try {
    obj.reset(new HostInformationTablePlugin());
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
