#include "socketeventstableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct SocketEventsTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status SocketEventsTablePlugin::create(Ref &obj,
                                       IZeekConfiguration &configuration,
                                       IZeekLogger &logger) {
  try {
    auto ptr = new SocketEventsTablePlugin(configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

SocketEventsTablePlugin::~SocketEventsTablePlugin() {}

const std::string &SocketEventsTablePlugin::name() const {
  static const std::string kTableName{"socket_events"};

  return kTableName;
}

const SocketEventsTablePlugin::Schema &SocketEventsTablePlugin::schema() const {

  static const Schema kTableSchema = {
      {"syscall", IVirtualTable::ColumnType::String},
      {"pid", IVirtualTable::ColumnType::Integer},
      {"ppid", IVirtualTable::ColumnType::Integer},
      {"auid", IVirtualTable::ColumnType::Integer},
      {"uid", IVirtualTable::ColumnType::Integer},
      {"euid", IVirtualTable::ColumnType::Integer},
      {"gid", IVirtualTable::ColumnType::Integer},
      {"egid", IVirtualTable::ColumnType::Integer},
      {"exe", IVirtualTable::ColumnType::String},
      {"fd", IVirtualTable::ColumnType::String},
      {"success", IVirtualTable::ColumnType::Integer},
      {"family", IVirtualTable::ColumnType::Integer},
      {"local_address", IVirtualTable::ColumnType::String},
      {"remote_address", IVirtualTable::ColumnType::String},
      {"local_port", IVirtualTable::ColumnType::Integer},
      {"remote_port", IVirtualTable::ColumnType::Integer},
      {"time", IVirtualTable::ColumnType::Integer}};

  return kTableSchema;
}

Status SocketEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status SocketEventsTablePlugin::processEvents(
    const IAudispConsumer::AuditEventList &event_list) {
  RowList generated_row_list;

  for (const auto &audit_event : event_list) {
    Row row;

    auto status = generateRow(row, audit_event);
    if (!status.succeeded()) {
      return status;
    }

    if (!row.empty()) {
      {
        std::lock_guard<std::mutex> lock(d->row_list_mutex);
        d->row_list.push_back(row);
      }
    }
  }

  if (d->row_list.size() > d->max_queued_row_count) {

    auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

    d->logger.logMessage(IZeekLogger::Severity::Warning,
                         "socket_events: Dropping " +
                             std::to_string(rows_to_remove) +
                             " rows (max row count is set to " +
                             std::to_string(d->max_queued_row_count) + ")");

    {
      std::lock_guard<std::mutex> lock(d->row_list_mutex);
      d->row_list.erase(d->row_list.begin(),
                        std::next(d->row_list.begin(), rows_to_remove));
    }
  }

  return Status::success();
}

SocketEventsTablePlugin::SocketEventsTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {

  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status SocketEventsTablePlugin::generateRow(
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  std::string syscall_name;

  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Bind:
    syscall_name = "bind";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Connect:
    syscall_name = "connect";
    break;

  default:
    return Status::success();
  }

  if (!audit_event.sockaddr_data.has_value()) {
    return Status::failure("The AUDIT_SOCKADDR record was not found");
  }

  const auto &syscall_data = audit_event.syscall_data;
  const auto &sockaddr_data = audit_event.sockaddr_data.value();

  row["syscall"] = std::move(syscall_name);
  row["pid"] = syscall_data.process_id;
  row["ppid"] = syscall_data.parent_process_id;
  row["auid"] = syscall_data.auid;
  row["uid"] = syscall_data.uid;
  row["euid"] = syscall_data.euid;
  row["gid"] = syscall_data.gid;
  row["egid"] = syscall_data.egid;
  row["exe"] = syscall_data.exe;

  auto fd = std::strtoll(syscall_data.a0.c_str(), nullptr, 16U);
  row["fd"] = static_cast<std::int64_t>(fd);

  row["success"] =
      static_cast<std::int64_t>(audit_event.syscall_data.succeeded ? 1 : 0);

  row["family"] = sockaddr_data.family;

  // TODO: remote_address/remote_port and local_address/local_port
  // should be set to {} when not used (so that SQLite will return
  // a NULL value). This is however not yet supported by the Zeek
  // scripts, so we'll just return empty strings
  std::int64_t null_value{0};

  if (audit_event.syscall_data.type ==
      IAudispConsumer::SyscallRecordData::Type::Bind) {

    row["local_address"] = sockaddr_data.address;
    row["local_port"] = sockaddr_data.port;

    row["remote_address"] = {""};
    row["remote_port"] = {null_value};

  } else {
    row["local_address"] = {""};
    row["local_port"] = {null_value};

    row["remote_address"] = sockaddr_data.address;
    row["remote_port"] = sockaddr_data.port;
  }

  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  row["time"] = static_cast<std::int64_t>(current_timestamp.count());

  return Status::success();
}
} // namespace zeek
