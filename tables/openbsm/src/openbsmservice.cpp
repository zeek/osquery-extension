#include "openbsmservice.h"
#include "socketeventstableplugin.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

#include <zeek/iopenbsmconsumer.h>
#include <zeek/openbsmservicefactory.h>

namespace zeek {
namespace {
const std::string kServiceName{"openbsm"};
} // namespace

struct OpenbsmService::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  IOpenbsmConsumer::Ref openbsm_consumer;

  IVirtualTable::Ref socket_events_table;
};

OpenbsmService::~OpenbsmService() {
  if (d->socket_events_table) {
    auto status =
        d->virtual_database.unregisterTable(d->socket_events_table->name());
    assert(status.succeeded() &&
           "Failed to unregister the socket_events table");
  }
}

const std::string &OpenbsmService::name() const { return kServiceName; }

Status OpenbsmService::exec(std::atomic_bool &terminate) {

  while (!terminate) {

    if (!d->socket_events_table) {
      d->logger.logMessage(IZeekLogger::Severity::Information,
                           "Table(s) not created yet, sleeping for 1 second");
      std::this_thread::sleep_for(std::chrono::seconds(1U));
      continue;
    }

    auto &socket_events_table_impl =
        *static_cast<SocketEventsTablePlugin *>(d->socket_events_table.get());

    IOpenbsmConsumer::EventList event_list;

    d->openbsm_consumer->getEvents(event_list);

    if (event_list.empty()) {
      continue;
    }

    auto status = socket_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The socket_events table failed to process some events: " +
              status.message());
    }
  }

  return Status::success();
}

OpenbsmService::OpenbsmService(IVirtualDatabase &virtual_database,
                               IZeekConfiguration &configuration,
                               IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {

  auto status =
      IOpenbsmConsumer::create(d->openbsm_consumer, logger, configuration);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Failed to connect to the Openbsm API. The "
                         "socket_events tables will not be enabled. Error: " +
                             status.message());

    return;
  }

  status = SocketEventsTablePlugin::create(d->socket_events_table,
                                           configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->socket_events_table);
  if (!status.succeeded()) {
    throw status;
  }
}

struct OpenbsmServiceFactory::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;
};

Status OpenbsmServiceFactory::create(Ref &obj,
                                     IVirtualDatabase &virtual_database,
                                     IZeekConfiguration &configuration,
                                     IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr =
        new OpenbsmServiceFactory(virtual_database, configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

OpenbsmServiceFactory::~OpenbsmServiceFactory() {}

const std::string &OpenbsmServiceFactory::name() const { return kServiceName; }

Status OpenbsmServiceFactory::spawn(IZeekService::Ref &obj) {
  obj.reset();

  try {
    obj.reset(
        new OpenbsmService(d->virtual_database, d->configuration, d->logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

OpenbsmServiceFactory::OpenbsmServiceFactory(IVirtualDatabase &virtual_database,
                                             IZeekConfiguration &configuration,
                                             IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}

} // namespace zeek
