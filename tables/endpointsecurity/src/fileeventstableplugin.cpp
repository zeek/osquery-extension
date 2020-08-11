#include "fileeventstableplugin.h"

#include <chrono>
#include <limits>
#include <mutex>

namespace zeek {
struct FileEventsTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status FileEventsTablePlugin::create(Ref &obj,
                                     IZeekConfiguration &configuration,
                                     IZeekLogger &logger) {

  try {
    obj.reset(new FileEventsTablePlugin(configuration, logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

FileEventsTablePlugin::~FileEventsTablePlugin() {}

const std::string &FileEventsTablePlugin::name() const {
  static const std::string kTableName{"file_events"};

  return kTableName;
}

const FileEventsTablePlugin::Schema &FileEventsTablePlugin::schema() const {

  static const Schema kTableSchema = {
      {"timestamp", IVirtualTable::ColumnType::Integer},
      {"type", IVirtualTable::ColumnType::String},
      {"parent_process_id", IVirtualTable::ColumnType::Integer},
      {"orig_parent_process_id", IVirtualTable::ColumnType::Integer},
      {"process_id", IVirtualTable::ColumnType::Integer},
      {"user_id", IVirtualTable::ColumnType::Integer},
      {"group_id", IVirtualTable::ColumnType::Integer},
      {"platform_binary", IVirtualTable::ColumnType::Integer},
      {"signing_id", IVirtualTable::ColumnType::String},
      {"team_id", IVirtualTable::ColumnType::String},
      {"cdhash", IVirtualTable::ColumnType::String},
      {"path", IVirtualTable::ColumnType::String},
      {"file_path", IVirtualTable::ColumnType::String}};

  return kTableSchema;
}

Status FileEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status FileEventsTablePlugin::processEvents(
    const IEndpointSecurityConsumer::EventList &event_list) {

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

    std::lock_guard<std::mutex> lock(d->row_list_mutex);
    
    if (d->row_list.size() > d->max_queued_row_count) {
      auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

      d->logger.logMessage(IZeekLogger::Severity::Warning,
                           "file_events: Dropping " +
                               std::to_string(rows_to_remove) +
                               " rows (max row count is set to " +
                               std::to_string(d->max_queued_row_count) + ")");

      d->row_list.erase(d->row_list.begin(),
                        std::next(d->row_list.begin(), rows_to_remove));
    }

  }

  return Status::success();
}

FileEventsTablePlugin::FileEventsTablePlugin(IZeekConfiguration &configuration,
                                             IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {
  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status FileEventsTablePlugin::generateRow(
    Row &row, const IEndpointSecurityConsumer::Event &event) {

  row = {};

  std::string action;

  switch (event.type) {
  case IEndpointSecurityConsumer::Event::Type::Open:
    action = "open";
    break;
  case IEndpointSecurityConsumer::Event::Type::Create:
    action = "create";
    break;

  case IEndpointSecurityConsumer::Event::Type::Exec:
  case IEndpointSecurityConsumer::Event::Type::Fork:
    return Status::success();
  }
  const auto &header = event.header;
  assert((header.timestamp <= std::numeric_limits<int64_t>::max()) &&
         "Failed to cast timestamp to int64_t");
  row["timestamp"] = static_cast<std::int64_t>(header.timestamp);
  row["parent_process_id"] =
      static_cast<std::int64_t>(header.parent_process_id);
  row["orig_parent_process_id"] =
      static_cast<std::int64_t>(header.orig_parent_process_id);
  row["process_id"] = static_cast<std::int64_t>(header.process_id);
  row["user_id"] = static_cast<std::int64_t>(header.user_id);
  row["group_id"] = static_cast<std::int64_t>(header.group_id);
  row["platform_binary"] = static_cast<std::int64_t>(header.platform_binary);
  row["signing_id"] = header.signing_id;
  row["team_id"] = header.team_id;
  row["cdhash"] = header.cdhash;
  row["path"] = header.path;
  row["file_path"] = header.file_path;
  row["type"] = std::move(action);

  return Status::success();
}
} // namespace zeek
