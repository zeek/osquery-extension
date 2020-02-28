#include "endpointsecurityservice.h"
#include "processeventstableplugin.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <thread>

#include <zeek/endpointsecurityservicefactory.h>
#include <zeek/iendpointsecurityconsumer.h>

namespace zeek {
namespace {
const std::string kServiceName{"endpointsecurity"};
} // namespace

struct EndpointSecurityService::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;

  IEndpointSecurityConsumer::Ref endpoint_sec_consumer;

  IVirtualTable::Ref process_events_table;
};

EndpointSecurityService::~EndpointSecurityService() {
  if (!d->process_events_table) {
    return;
  }

  auto status =
      d->virtual_database.unregisterTable(d->process_events_table->name());

  assert(status.succeeded() && "Failed to unregister the process_events table");
}

const std::string &EndpointSecurityService::name() const {
  return kServiceName;
}

Status EndpointSecurityService::exec(std::atomic_bool &terminate) {
  while (!terminate) {
    if (!d->process_events_table) {
      std::this_thread::sleep_for(std::chrono::seconds(1U));
      continue;
    }

    auto &process_events_table_impl =
        *static_cast<ProcessEventsTablePlugin *>(d->process_events_table.get());

    IEndpointSecurityConsumer::EventList event_list;
    d->endpoint_sec_consumer->getEvents(event_list);

    if (event_list.empty()) {
      continue;
    }

    auto status = process_events_table_impl.processEvents(event_list);
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The process_events table failed to process some events: " +
              status.message());
    }
  }

  return Status::success();
}

EndpointSecurityService::EndpointSecurityService(
    IVirtualDatabase &virtual_database, IZeekConfiguration &configuration,
    IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {

  auto status = IEndpointSecurityConsumer::create(d->endpoint_sec_consumer,
                                                  logger, configuration);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Failed to connect to the EndpointSecurity API. The "
                         "process_events table will not be enabled. Error: " +
                             status.message());

    return;
  }

  status = ProcessEventsTablePlugin::create(d->process_events_table,
                                            configuration, logger);
  if (!status.succeeded()) {
    throw status;
  }

  status = d->virtual_database.registerTable(d->process_events_table);
  if (!status.succeeded()) {
    throw status;
  }
}

struct EndpointSecurityServiceFactory::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_,
              IZeekConfiguration &configuration_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), configuration(configuration_),
        logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekConfiguration &configuration;
  IZeekLogger &logger;
};

Status EndpointSecurityServiceFactory::create(
    Ref &obj, IVirtualDatabase &virtual_database,
    IZeekConfiguration &configuration, IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr = new EndpointSecurityServiceFactory(virtual_database,
                                                  configuration, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

EndpointSecurityServiceFactory::~EndpointSecurityServiceFactory() {}

const std::string &EndpointSecurityServiceFactory::name() const {
  return kServiceName;
}

Status EndpointSecurityServiceFactory::spawn(IZeekService::Ref &obj) {
  obj.reset();

  try {
    obj.reset(new EndpointSecurityService(d->virtual_database, d->configuration,
                                          d->logger));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

EndpointSecurityServiceFactory::EndpointSecurityServiceFactory(
    IVirtualDatabase &virtual_database, IZeekConfiguration &configuration,
    IZeekLogger &logger)
    : d(new PrivateData(virtual_database, configuration, logger)) {}
} // namespace zeek
