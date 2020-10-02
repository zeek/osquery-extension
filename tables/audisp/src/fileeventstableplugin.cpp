#include "fileeventstableplugin.h"

#include <chrono>
#include <filesystem>
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
    auto ptr = new FileEventsTablePlugin(configuration, logger);
    obj.reset(ptr);

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
      {"syscall", IVirtualTable::ColumnType::String},
      {"pid", IVirtualTable::ColumnType::Integer},
      {"ppid", IVirtualTable::ColumnType::Integer},
      {"uid", IVirtualTable::ColumnType::Integer},
      {"gid", IVirtualTable::ColumnType::Integer},
      {"auid", IVirtualTable::ColumnType::Integer},
      {"euid", IVirtualTable::ColumnType::Integer},
      {"egid", IVirtualTable::ColumnType::Integer},
      {"exe", IVirtualTable::ColumnType::String},
      {"path", IVirtualTable::ColumnType::String},
      {"inode", IVirtualTable::ColumnType::Integer},
      {"time", IVirtualTable::ColumnType::Integer}};

  return kTableSchema;
}

Status FileEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status FileEventsTablePlugin::processEvents(
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

std::string FileEventsTablePlugin::CombinePaths(const std::string &cwd,
                                                const std::string &path) {
  std::string full_path;

  // Quotes are only present when path contain space
  if (path[0] == '"') {
    full_path = path.substr(1, path.size() - 2);
  } else {
    full_path = path;
  }

  // Use cwd when path is not absolute
  if (full_path[0] != '/') {
    std::string normalized_cwd;

    if (cwd[0] == '"') {
      normalized_cwd = cwd.substr(1, cwd.size() - 2);
    } else {
      normalized_cwd = cwd;
    }

    full_path = std::filesystem::path(normalized_cwd) / full_path;
  }
  return full_path;
}

Status FileEventsTablePlugin::generateRow(
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  std::string syscall_name;
  std::string full_path;
  std::int64_t inode;
  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Open:
  case IAudispConsumer::SyscallRecordData::Type::OpenAt: {
    if (!audit_event.cwd_data.has_value()) {
      return Status::failure("Missing an AUDIT_CWD record from a file event");
    }
    if (!audit_event.path_data.has_value()) {
      return Status::failure("Missing an AUDIT_PATH record from a file event");
    }
    if (audit_event.syscall_data.type ==
        IAudispConsumer::SyscallRecordData::Type::Open)
      syscall_name = "open";
    else
      syscall_name = "openat";

    std::string working_dir_path;
    std::string file_path;
    const auto &path_record = audit_event.path_data.value();
    const auto &cwd_record = audit_event.cwd_data.value();

    if (path_record.size() == 1) {
      working_dir_path = cwd_record;
      file_path = path_record.at(0).path;
      inode = path_record.at(0).inode;

    } else if (path_record.size() == 2) {
      working_dir_path = path_record.at(0).path;
      file_path = path_record.at(1).path;
      inode = path_record.at(1).inode;

    } else if (path_record.size() == 3) {
      working_dir_path = cwd_record;
      file_path = path_record.at(0).path;
      inode = path_record.at(0).inode;

    } else {
      return Status::failure(
          "Wrong number of path records for open/openat syscall event");
    }
    full_path = CombinePaths(working_dir_path, file_path);
    break;
  }
  case IAudispConsumer::SyscallRecordData::Type::Create: {
    if (!audit_event.path_data.has_value()) {
      return Status::failure("Missing an AUDIT_PATH record from a file event");
    }
    syscall_name = "create";
    const auto &path_record = audit_event.path_data.value();
    if (path_record.size() != 2) {
      return Status::failure(
          "Wrong number of path records for create syscall event");
    }
    std::string working_dir_path = path_record.at(0).path;
    std::string file_path = path_record.at(1).path;
    full_path = CombinePaths(working_dir_path, file_path);
    inode = path_record.at(1).inode;
    break;
  }
  case IAudispConsumer::SyscallRecordData::Type::Execve:
  case IAudispConsumer::SyscallRecordData::Type::ExecveAt:
  case IAudispConsumer::SyscallRecordData::Type::Fork:
  case IAudispConsumer::SyscallRecordData::Type::VFork:
  case IAudispConsumer::SyscallRecordData::Type::Clone:
  case IAudispConsumer::SyscallRecordData::Type::Bind:
  case IAudispConsumer::SyscallRecordData::Type::Connect:
    return Status::success();
  }

  const auto &syscall_data = audit_event.syscall_data;

  row["syscall"] = std::move(syscall_name);
  row["pid"] = syscall_data.process_id;
  row["ppid"] = syscall_data.parent_process_id;
  row["uid"] = syscall_data.uid;
  row["gid"] = syscall_data.gid;
  row["auid"] = syscall_data.auid;
  row["euid"] = syscall_data.euid;
  row["egid"] = syscall_data.egid;
  row["exe"] = syscall_data.exe;
  row["path"] = std::move(full_path);
  row["inode"] = inode;
  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  row["time"] = static_cast<std::int64_t>(current_timestamp.count());

  return Status::success();
}
} // namespace zeek
