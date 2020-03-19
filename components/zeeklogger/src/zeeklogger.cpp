#include "zeeklogger.h"
#include "zeekloggertableplugin.h"

#include <cassert>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include <zeek/time.h>

namespace zeek {
namespace {
std::string getCurrentTimestamp(const std::string &format) {
  auto current_time = std::time(nullptr);

  struct tm current_time_tm {};
  getLocalTime(&current_time, &current_time_tm);

  std::stringstream buffer;
  buffer << std::put_time(&current_time_tm, format.c_str());

  return buffer.str();
}

std::string generateLogFileName(const std::string &base_path) {
  return base_path + "/" + getCurrentTimestamp("%Y%m%d_%H%M%S") + ".log";
}
} // namespace

struct ZeekLogger::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_)
      : virtual_database(virtual_database_) {}

  Configuration configuration;
  IVirtualDatabase &virtual_database;

  ZeekLoggerTablePlugin::Ref logger_table;

  std::mutex log_file_mutex;
  std::fstream log_file;
};

ZeekLogger::~ZeekLogger() {
  auto status = unregisterTables();

  assert(status.succeeded() &&
         "Failed to unregister the logger tables from the virtual database");
}

void ZeekLogger::logMessage(Severity severity, const std::string &message) {
  auto &logger_table_impl =
      *static_cast<ZeekLoggerTablePlugin *>(d->logger_table.get());

  if (severity < d->configuration.severity_filter) {
    return;
  }

  std::lock_guard<std::mutex> lock(d->log_file_mutex);

  if (!d->log_file.is_open() || d->log_file.fail()) {
    d->log_file = {};

    auto log_file_path = generateLogFileName(d->configuration.log_folder);

    d->log_file.open(log_file_path, std::ios::out);
    if (!d->log_file.good()) {
      auto error_message = "Failed to open the log file: " + log_file_path;

      auto status =
          logger_table_impl.appendMessage(Severity::Error, error_message);

      std::cerr << error_message << "\n";

      d->log_file = {};
    }
  }

  auto status = logger_table_impl.appendMessage(severity, message);
  if (!status.succeeded()) {
    std::cerr << "Failed to log the following message to the logger table: "
              << message << "\n";
  }

  std::ostream &output_stream = d->log_file.is_open() ? d->log_file : std::cerr;
  output_stream << getCurrentTimestamp("%Y-%m-%d %H:%M:%S") << " "
                << loggerSeverityToString(severity) << ": " << message
                << std::endl;
}

ZeekLogger::ZeekLogger(const Configuration &configuration,
                       IVirtualDatabase &virtual_database)
    : d(new PrivateData(virtual_database)) {

  d->configuration = configuration;

  auto status = registerTables();
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekLogger::registerTables() {
  auto status = ZeekLoggerTablePlugin::create(d->logger_table);
  if (!status.succeeded()) {
    return status;
  }

  status = d->virtual_database.registerTable(d->logger_table);
  if (!status.succeeded()) {
    d->logger_table.reset();
    return status;
  }

  return Status::success();
}

Status ZeekLogger::unregisterTables() {
  auto status = d->virtual_database.unregisterTable(d->logger_table->name());
  if (!status.succeeded()) {
    return status;
  }

  d->logger_table.reset();
  return Status::success();
}

Status IZeekLogger::create(Ref &ref, const Configuration &configuration,
                           IVirtualDatabase &virtual_database) {
  try {
    ref.reset();

    auto ptr = new ZeekLogger(configuration, virtual_database);
    ref.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

const std::string &
loggerSeverityToString(const IZeekLogger::Severity &severity) {
  // clang-format on
  static const std::unordered_map<IZeekLogger::Severity, std::string>
      kSeverityToString = {{IZeekLogger::Severity::Debug, "Debug"},
                           {IZeekLogger::Severity::Information, "Information"},
                           {IZeekLogger::Severity::Warning, "Warning"},
                           {IZeekLogger::Severity::Error, "Error"}};
  // clang-format on

  static const std::string kInvalidSeverityName{"Unknown"};

  auto severity_it = kSeverityToString.find(severity);
  if (severity_it == kSeverityToString.end()) {
    return kInvalidSeverityName;
  }

  return severity_it->second;
}
} // namespace zeek
