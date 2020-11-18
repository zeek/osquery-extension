#include "socketeventstableplugin.h"

#include <chrono>
#include <limits>
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
    obj.reset(new SocketEventsTablePlugin(configuration, logger));

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
      {"timestamp", IVirtualTable::ColumnType::Integer},
      {"type", IVirtualTable::ColumnType::String},
      {"process_id", IVirtualTable::ColumnType::Integer},
      {"user_id", IVirtualTable::ColumnType::Integer},
      {"group_id", IVirtualTable::ColumnType::Integer},
      {"path", IVirtualTable::ColumnType::String},
      {"family", IVirtualTable::ColumnType::Integer},
      {"success", IVirtualTable::ColumnType::Integer},
      {"local_address", IVirtualTable::ColumnType::String},
      {"local_port", IVirtualTable::ColumnType::Integer},
      {"remote_address", IVirtualTable::ColumnType::String},
      {"remote_port", IVirtualTable::ColumnType::Integer}};

  return kTableSchema;
}

Status SocketEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status SocketEventsTablePlugin::processEvents(
    const IOpenbsmConsumer::EventList &event_list) {

  for (const auto &event : event_list) {
    Row row;

    auto status = generateRow(row, event);
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

Status
SocketEventsTablePlugin::generateRow(Row &row,
                                     const IOpenbsmConsumer::Event &event) {

  row = {};

  std::string action;

  switch (event.type) {
  case IOpenbsmConsumer::Event::Type::Bind:
    action = "bind";
    break;
  case IOpenbsmConsumer::Event::Type::Connect:
    action = "connect";
    break;
  default:
    return Status::success();
  }
  const auto &header = event.header;
  assert((header.timestamp <= std::numeric_limits<int64_t>::max()) &&
         "Failed to cast timestamp to int64_t");
  row["timestamp"] = static_cast<std::int64_t>(header.timestamp);
  row["type"] = std::move(action);
  row["process_id"] = static_cast<std::int64_t>(header.process_id);
  row["user_id"] = static_cast<std::int64_t>(header.user_id);
  row["group_id"] = static_cast<std::int64_t>(header.group_id);
  row["path"] = header.path;
  row["family"] = static_cast<std::int64_t>(header.family);
  row["success"] = static_cast<std::int64_t>(header.success);

  std::int64_t null_value{0};

  if (event.type == IOpenbsmConsumer::Event::Type::Bind) {

    row["local_address"] = header.local_address;
    row["local_port"] = static_cast<std::int64_t>(header.local_port);

    row["remote_address"] = {""};
    row["remote_port"] = {null_value};

  } else {
    row["local_address"] = {""};
    row["local_port"] = {null_value};

    row["remote_address"] = header.remote_address;
    row["remote_port"] = static_cast<std::int64_t>(header.remote_port);
  }

  return Status::success();
}
} // namespace zeek
