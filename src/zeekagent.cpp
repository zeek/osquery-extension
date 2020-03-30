#include "zeekagent.h"
#include "configuration.h"
#include "logger.h"
#include "zeekconnection.h"

#include <chrono>
#include <thread>

#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
#include <zeek/iosqueryinterface.h>
#endif

#if defined(ZEEK_AGENT_PLATFORM_LINUX)
#include <zeek/audispservicefactory.h>
#elif defined(ZEEK_AGENT_PLATFORM_MACOS)
#include <zeek/endpointsecurityservicefactory.h>
#endif

#include <zeek/ihostinformationtableplugin.h>
#include <zeek/system_identifiers.h>

namespace zeek {
struct ZeekAgent::PrivateData final {
  IVirtualDatabase::Ref virtual_database;
  std::string host_identifier;
  std::vector<IVirtualTable::Ref> internal_table_list;
};

Status ZeekAgent::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new ZeekAgent();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekAgent::~ZeekAgent() { deinitializeTables(); }

Status ZeekAgent::exec(std::atomic_bool &terminate) {
  auto status = getHostUUID(d->host_identifier);
  if (!status.succeeded()) {
    getLogger().logMessage(IZeekLogger::Severity::Error,
                           status.message() + ". Using the hostname instead");

    d->host_identifier = getSystemHostname();
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Host identifier: " + d->host_identifier);

  IZeekServiceManager::Ref service_manager;
  status = initializeServiceManager(service_manager);
  if (!status.succeeded()) {
    return status;
  }

  status = service_manager->startServices();
  if (!status.succeeded()) {
    return status;
  }

  ZeekConnection::Ref zeek_connection;
  QueryScheduler::Ref query_scheduler;

#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
  auto osquery_socket = getConfig().osqueryExtensionsSocket();

  IOsqueryInterface::Ref osquery_interface;
  status =
      IOsqueryInterface::create(osquery_interface, *d->virtual_database.get(),
                                getLogger(), osquery_socket);

  if (!status.succeeded()) {
    return status;
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Starting the osquery integration");

  status = osquery_interface->start();
  if (!status.succeeded()) {
    return status;
  }
#endif

  while (!terminate) {
    service_manager->checkServices();

    if (zeek_connection && query_scheduler) {
      status = zeek_connection->processEvents();

      if (!status.succeeded()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "The connection has been lost: " +
                                   status.message());

        zeek_connection.reset();

        query_scheduler->stop();
        query_scheduler.reset();

        continue;
      }

    } else {
      status = initializeConnection(zeek_connection);

      if (!status.succeeded()) {
        getLogger().logMessage(
            IZeekLogger::Severity::Error,
            "Reconnecting has failed. Retrying again later...");

        std::this_thread::sleep_for(std::chrono::seconds(5));
        continue;
      }

      status = initializeQueryScheduler(query_scheduler);
      if (!status.succeeded()) {
        status = Status::failure("Failed to initialize the query scheduler");

        getLogger().logMessage(IZeekLogger::Severity::Error, status.message());
        return status;
      }
    }

    auto task_queue = zeek_connection->getTaskQueue();
    query_scheduler->processTaskQueue(std::move(task_queue));

    auto task_output_list = query_scheduler->getTaskOutputList();
    if (!task_output_list.empty()) {
      status = zeek_connection->processTaskOutputList(std::move(task_output_list));

      if (!status.succeeded()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "Failed to process the task output list: " +
                                   status.message());
      }
    }
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Stopping all services");

  if (zeek_connection) {
    zeek_connection.reset();
  }

#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
  osquery_interface->stop();
  osquery_interface.reset();
#endif

  if (query_scheduler) {
    query_scheduler->stop();
    query_scheduler.reset();
  }

  service_manager->stopServices();
  service_manager.reset();

  getLogger().logMessage(IZeekLogger::Severity::Information, "Terminating");
  return Status::success();
}

IVirtualDatabase &ZeekAgent::virtualDatabase() {
  return *d->virtual_database.get();
}

ZeekAgent::ZeekAgent() : d(new PrivateData) {
  auto status = IVirtualDatabase::create(d->virtual_database);
  if (!status.succeeded()) {
    throw status;
  }

  status = initializeTables();
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekAgent::initializeConnection(ZeekConnection::Ref &zeek_connection) {
  zeek_connection.reset();

  auto status = ZeekConnection::create(zeek_connection, d->host_identifier);
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status
ZeekAgent::initializeQueryScheduler(QueryScheduler::Ref &query_scheduler) {
  if (query_scheduler) {
    query_scheduler->stop();
    query_scheduler.reset();
  }

  auto status =
      QueryScheduler::create(query_scheduler, *d->virtual_database.get());

  if (!status.succeeded()) {
    return status;
  }

  status = query_scheduler->start();
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status
ZeekAgent::initializeServiceManager(IZeekServiceManager::Ref &service_manager) {
  auto &virtual_database = *d->virtual_database.get();

  auto status = IZeekServiceManager::create(service_manager, virtual_database,
                                            getLogger());

  if (!status.succeeded()) {
    throw status;
  }

#if defined(ZEEK_AGENT_PLATFORM_LINUX)
  status = registerAudispServiceFactory(
      *service_manager.get(), virtual_database, getConfig(), getLogger());

  if (!status.succeeded()) {
    throw status;
  }

#elif defined(ZEEK_AGENT_PLATFORM_MACOS)
  status = registerEndpointSecurityServiceFactory(
      *service_manager.get(), virtual_database, getConfig(), getLogger());

  if (!status.succeeded()) {
    getLogger().logMessage(
        IZeekLogger::Severity::Error,
        "The EndpointSecurity tables could not be initialized: " +
            status.message());

    throw status;
  }
#endif

  return Status::success();
}

Status ZeekAgent::initializeTables() {
  IVirtualTable::Ref table_ref;
  auto status = IHostInformationTablePlugin::create(table_ref);
  if (!status.succeeded()) {
    return status;
  }

  status = d->virtual_database->registerTable(table_ref);
  if (!status.succeeded()) {
    return status;
  }

  d->internal_table_list.push_back(table_ref);
  return Status::success();
}

void ZeekAgent::deinitializeTables() {
  for (const auto &table : d->internal_table_list) {
    d->virtual_database->unregisterTable(table->name());
  }
}
} // namespace zeek
