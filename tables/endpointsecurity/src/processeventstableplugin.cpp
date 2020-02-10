#include "processeventstableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct ProcessEventsTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : configuration(configuration_), logger(logger_) {}

  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  RowList row_list;
  std::mutex row_list_mutex;
  std::size_t max_queued_row_count{0U};
};

Status ProcessEventsTablePlugin::create(Ref &obj,
                                        IZeekConfiguration &configuration,
                                        IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr = new ProcessEventsTablePlugin(configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ProcessEventsTablePlugin::~ProcessEventsTablePlugin() {}

const std::string &ProcessEventsTablePlugin::name() const {
  static const std::string kTableName{"process_events"};

  return kTableName;
}

const ProcessEventsTablePlugin::Schema &
ProcessEventsTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "syscall", IVirtualTable::ColumnType::String },
    { "pid", IVirtualTable::ColumnType::Integer },
    { "parent", IVirtualTable::ColumnType::Integer },
    { "auid", IVirtualTable::ColumnType::Integer },
    { "uid", IVirtualTable::ColumnType::Integer },
    { "euid", IVirtualTable::ColumnType::Integer },
    { "gid", IVirtualTable::ColumnType::Integer },
    { "egid", IVirtualTable::ColumnType::Integer },
    { "owner_uid", IVirtualTable::ColumnType::Integer },
    { "owner_gid", IVirtualTable::ColumnType::Integer },
    { "cmdline_size", IVirtualTable::ColumnType::Integer },
    { "cmdline", IVirtualTable::ColumnType::String },
    { "path", IVirtualTable::ColumnType::String },
    { "mode", IVirtualTable::ColumnType::String },
    { "cwd", IVirtualTable::ColumnType::String },
    { "time", IVirtualTable::ColumnType::Integer }
  };
  // clang-format on

  return kTableSchema;
}

Status ProcessEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status ProcessEventsTablePlugin::processEvents(
    const IEndpointSecurityConsumer::EventList &event_list) {
  RowList generated_row_list;

  for (const auto &event : event_list) {
    Row row;

    auto status = generateRow(row, event);
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
                           "process_events: Dropping " +
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

ProcessEventsTablePlugin::ProcessEventsTablePlugin(
    IZeekConfiguration &configuration, IZeekLogger &logger)
    : d(new PrivateData(configuration, logger)) {

  d->max_queued_row_count = d->configuration.maxQueuedRowCount();
}

Status ProcessEventsTablePlugin::generateRow(
    Row &row, const IEndpointSecurityConsumer::Event &event) {

  row = {};

  // TODO(alessandro): Add the remaining fields
  row["pid"] = static_cast<std::int64_t>(0);
  row["parent"] = static_cast<std::int64_t>(0);
  row["auid"] = static_cast<std::int64_t>(0);
  row["uid"] = static_cast<std::int64_t>(0);
  row["euid"] = static_cast<std::int64_t>(0);
  row["gid"] = static_cast<std::int64_t>(0);
  row["egid"] = static_cast<std::int64_t>(0);
  row["owner_uid"] = static_cast<std::int64_t>(0);
  row["owner_gid"] = static_cast<std::int64_t>(0);
  row["cmdline_size"] = static_cast<std::int64_t>(0);
  row["cmdline"] = "";
  row["path"] = "";
  row["mode"] = static_cast<std::int64_t>(0);
  row["cwd"] = "";

  row["time"] = static_cast<std::int64_t>(0);

  if (std::holds_alternative<IEndpointSecurityConsumer::Event::ExecEventData>(
          event.data)) {
    const auto &exec_event_data =
        std::get<IEndpointSecurityConsumer::Event::ExecEventData>(event.data);

    row["syscall"] = "exec";
    row["path"] = exec_event_data.path;

  } else if (std::holds_alternative<
                 IEndpointSecurityConsumer::Event::ForkEventData>(event.data)) {
    const auto &fork_event_data =
        std::get<IEndpointSecurityConsumer::Event::ForkEventData>(event.data);
    static_cast<void>(fork_event_data);

    row["syscall"] = "fork";

  } else {
    return Status::failure("Invalid event");
  }

  return Status::success();
}
} // namespace zeek
