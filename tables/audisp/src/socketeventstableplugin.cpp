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
  obj.reset();

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
  // clang-format off
  static const Schema kTableSchema = {
    { "action", IVirtualTable::ColumnType::String },
    { "pid", IVirtualTable::ColumnType::Integer },
    { "path", IVirtualTable::ColumnType::String },
    { "fd", IVirtualTable::ColumnType::String },
    { "auid", IVirtualTable::ColumnType::Integer },
    { "success", IVirtualTable::ColumnType::Integer },
    { "family", IVirtualTable::ColumnType::Integer },
    { "local_address", IVirtualTable::ColumnType::String },
    { "remote_address", IVirtualTable::ColumnType::String },
    { "local_port", IVirtualTable::ColumnType::Integer },
    { "remote_port", IVirtualTable::ColumnType::Integer },
    { "time", IVirtualTable::ColumnType::Integer }
  };
  // clang-format on

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
      generated_row_list.push_back(std::move(row));
    }
  }

  {
    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    // clang-format off
    d->row_list.insert(
      d->row_list.end(),
      std::make_move_iterator(generated_row_list.begin()), 
      std::make_move_iterator(generated_row_list.end())
    );
    // clang-format on

    if (d->row_list.size() > d->max_queued_row_count) {
      auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

      d->logger.logMessage(IZeekLogger::Severity::Warning,
                           "socket_events: Dropping " +
                               std::to_string(rows_to_remove) +
                               " rows (max row count is set to " +
                               std::to_string(d->max_queued_row_count));

      // clang-format off
      d->row_list.erase(
        d->row_list.begin(),
        std::next(d->row_list.begin(), rows_to_remove)
      );
      // clang-format on
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

  std::string action;

  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Bind:
    action = "bind";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Connect:
    action = "connect";
    break;

  default:
    return Status::success();
  }

  if (!audit_event.sockaddr_data.has_value()) {
    return Status::failure("The AUDIT_SOCKADDR record was not found");
  }

  const auto &syscall_data = audit_event.syscall_data;
  const auto &sockaddr_data = audit_event.sockaddr_data.value();

  row["action"] = action;
  row["pid"] = syscall_data.process_id;
  row["path"] = syscall_data.exe;

  auto fd = std::strtoll(syscall_data.a0.c_str(), nullptr, 16U);
  row["fd"] = static_cast<std::int64_t>(fd);

  row["auid"] = syscall_data.auid;

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
