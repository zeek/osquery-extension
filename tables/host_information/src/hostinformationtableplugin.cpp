#include "hostinformationtableplugin.h"
#include "osversion.h"

#include <zeek/system_identifiers.h>

#include <broker/version.hh>

#include <errno.h>
#include <sys/utsname.h>

namespace zeek {
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

  struct utsname uname_info {};
  if (uname(&uname_info) != 0) {
    return Status::failure(
        "The uname() system function has failed with errno " +
        std::to_string(errno));
  }

  row["os_name"] = uname_info.sysname;
  row["os_version"] = uname_info.version;
  row["os_release"] = uname_info.release;
  row["os_machine"] = uname_info.machine;

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
