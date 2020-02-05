#include "audispservice.h"
#include "processeventstableplugin.h"
#include "socketeventstableplugin.h"

#include <algorithm>
#include <cassert>

#include <zeek/audispservicefactory.h>
#include <zeek/iaudispconsumer.h>

namespace zeek {
namespace {
const std::string kAudispSocketPath{"/var/run/audispd_events"};
const std::string kServiceName{"audisp"};
} // namespace

struct AudispService::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  zeek::IAudispConsumer::Ref audisp_consumer;

  IVirtualTable::Ref process_events_table;
  IVirtualTable::Ref socket_events_table;
};

AudispService::~AudispService() {
  auto status =
      d->virtual_database.unregisterTable(d->process_events_table->name());

  assert(status.succeeded() && "Failed to unregister the process_events table");

  status = d->virtual_database.unregisterTable(d->socket_events_table->name());
  assert(status.succeeded() && "Failed to unregister the socket_events table");
}

const std::string &AudispService::name() const { return kServiceName; }

Status AudispService::exec(std::atomic_bool &terminate) {
  auto &process_events_table_impl =
      *static_cast<ProcessEventsTablePlugin *>(d->process_events_table.get());

  auto &socket_events_table_impl =
      *static_cast<SocketEventsTablePlugin *>(d->socket_events_table.get());

  while (!terminate) {
    auto status = d->audisp_consumer->processEvents();
    if (!status.succeeded()) {
      return status;
    }

    IAudispConsumer::AuditEventList event_list;
    d->audisp_consumer->getEvents(event_list);

    if (event_list.empty()) {
      continue;
    }

    status = process_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The process_events table failed to process some events: " +
              status.message());
    }

    status = socket_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The socket_events table failed to process some events: " +
              status.message());
    }
  }

  return Status::success();
}

AudispService::AudispService(IVirtualDatabase &virtual_database,
                             IZeekConfiguration &configuration,
                             IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {

  auto status =
      zeek::IAudispConsumer::create(d->audisp_consumer, kAudispSocketPath);

  if (!status.succeeded()) {
    throw status;
  }

  status = ProcessEventsTablePlugin::create(d->process_events_table,
                                            configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = SocketEventsTablePlugin::create(d->socket_events_table,
                                           configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->process_events_table);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->socket_events_table);
  if (!status.succeeded()) {
    throw status;
  }
}

struct AudispServiceFactory::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;
};

Status AudispServiceFactory::create(Ref &obj,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr =
        new AudispServiceFactory(virtual_database, configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AudispServiceFactory::~AudispServiceFactory() {}

const std::string &AudispServiceFactory::name() const { return kServiceName; }

Status AudispServiceFactory::spawn(IZeekService::Ref &obj) {
  obj.reset();

  try {
    auto ptr =
        new AudispService(d->virtual_database, d->configuration, d->logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AudispServiceFactory::AudispServiceFactory(IVirtualDatabase &virtual_database,
                                           IZeekConfiguration &configuration,
                                           IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}
} // namespace zeek
