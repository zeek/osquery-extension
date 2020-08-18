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
  static const Schema kTableSchema = {
      // Present in the AUDIT_SYSCALL record
      {"syscall", IVirtualTable::ColumnType::String},
      {"pid", IVirtualTable::ColumnType::Integer},
      {"ppid", IVirtualTable::ColumnType::Integer},
      {"auid", IVirtualTable::ColumnType::Integer},
      {"uid", IVirtualTable::ColumnType::Integer},
      {"euid", IVirtualTable::ColumnType::Integer},
      {"gid", IVirtualTable::ColumnType::Integer},
      {"egid", IVirtualTable::ColumnType::Integer},
      {"exe", IVirtualTable::ColumnType::String},
      {"exit", IVirtualTable::ColumnType::Integer},

      // Present in the AUDIT_EXECVE record(s)
      {"cmdline", IVirtualTable::ColumnType::String},

      // Present in the AUDIT_PATH record(s)
      {"path", IVirtualTable::ColumnType::String},
      {"mode", IVirtualTable::ColumnType::Integer},
      {"inode", IVirtualTable::ColumnType::Integer},
      {"ouid", IVirtualTable::ColumnType::Integer},
      {"ogid", IVirtualTable::ColumnType::Integer},

      // Present in the AUDIT_CWD record
      {"cwd", IVirtualTable::ColumnType::String},

      // Custom
      {"time", IVirtualTable::ColumnType::Integer}};

  return kTableSchema;
}

Status ProcessEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status ProcessEventsTablePlugin::processEvents(
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

    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    if (d->row_list.size() > d->max_queued_row_count) {
      auto rows_to_remove = d->row_list.size() - d->max_queued_row_count;

      d->logger.logMessage(IZeekLogger::Severity::Warning,
                           "process_events: Dropping " +
                               std::to_string(rows_to_remove) +
                               " rows (max row count is set to " +
                               std::to_string(d->max_queued_row_count) + ")");

      d->row_list.erase(d->row_list.begin(),
                        std::next(d->row_list.begin(), rows_to_remove));
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
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  if (!audit_event.syscall_data.succeeded) {
    return Status::success();
  }

  const auto &syscall_data = audit_event.syscall_data;
  std::string syscall_name;

  switch (syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Execve:
    syscall_name = "execve";
    break;

  case IAudispConsumer::SyscallRecordData::Type::ExecveAt:
    syscall_name = "execveat";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Fork:
    syscall_name = "fork";
    break;

  case IAudispConsumer::SyscallRecordData::Type::VFork:
    syscall_name = "vfork";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Clone:
    syscall_name = "clone";
    break;
  case IAudispConsumer::SyscallRecordData::Type::Bind:
  case IAudispConsumer::SyscallRecordData::Type::Connect:
  case IAudispConsumer::SyscallRecordData::Type::Open:
  case IAudispConsumer::SyscallRecordData::Type::OpenAt:
  case IAudispConsumer::SyscallRecordData::Type::Create:
    return Status::success();
  }

  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  auto time_value = static_cast<std::int64_t>(current_timestamp.count());

  row["time"] = time_value;
  row["syscall"] = std::move(syscall_name);
  row["pid"] = syscall_data.process_id;
  row["ppid"] = syscall_data.parent_process_id;
  row["auid"] = syscall_data.auid;
  row["uid"] = syscall_data.uid;
  row["euid"] = syscall_data.euid;
  row["gid"] = syscall_data.gid;
  row["egid"] = syscall_data.egid;
  row["exe"] = syscall_data.exe;
  row["exit"] = syscall_data.exit_code;

  if (syscall_data.type == IAudispConsumer::SyscallRecordData::Type::Execve ||
      syscall_data.type == IAudispConsumer::SyscallRecordData::Type::ExecveAt) {

    if (!audit_event.execve_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_EXECVE record from an execve(at) event");
    }

    if (!audit_event.path_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_PATH record from an execve(at) event");
    }

    if (!audit_event.cwd_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_CWD record from an execve(at) event");
    }

    const auto &execve_data = audit_event.execve_data.value();
    std::string command_line;
    for (const auto &parameter : execve_data.argument_list) {
      if (!command_line.empty()) {
        command_line.push_back(' ');
      }

      command_line += "\"" + parameter + "\"";
    }

    row["cmdline"] = command_line;

    const auto &path_record = audit_event.path_data.value();
    const auto &last_path_entry = path_record.front();

    row["path"] = last_path_entry.path;
    row["mode"] = last_path_entry.mode;
    row["inode"] = last_path_entry.inode;
    row["ouid"] = last_path_entry.ouid;
    row["ogid"] = last_path_entry.ogid;

    const auto &cwd_data = audit_event.cwd_data.value();

    row["cwd"] = cwd_data;

  } else {
    // TODO: The correct approach is to set these fields to {} and
    // leave them empty. This will make the IVirtualDatabase actually
    // return NULL values when returning this row.
    //
    // The Zeek scripts we have do not support 'none' as a data type yet, so
    // we'll just set these values to either zero or an empty string
    std::int64_t null_value{0};

    row["cmdline"] = {""};
    row["path"] = {""};
    row["mode"] = {null_value};
    row["inode"] = {null_value};
    row["ouid"] = {null_value};
    row["ogid"] = {null_value};
    row["cwd"] = {""};
  }

  return Status::success();
}
} // namespace zeek
