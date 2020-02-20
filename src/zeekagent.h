#pragma once

#include "zeekconnection.h"

#include <atomic>
#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeekservicemanager.h>

namespace zeek {
/// \brief The main Zeek Agent class, handling connection and tables
class ZeekAgent final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief A reference to a Zeek Agent object
  using Ref = std::unique_ptr<ZeekAgent>;

  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \return A Status object
  static Status create(Ref &obj);

  /// \brief Destructor
  ~ZeekAgent();

  /// \brief Executes the service until it is interrupted
  /// \param terminate Set to true when the service must terminate
  /// \return A Status object
  Status exec(std::atomic_bool &terminate);

  /// \return A reference to the internal Virtual Database
  IVirtualDatabase &virtualDatabase();

  ZeekAgent(const ZeekAgent &) = delete;
  ZeekAgent &operator=(const ZeekAgent &) = delete;

protected:
  /// \brief Constructor
  ZeekAgent();

private:
  /// \brief Initializes the connection with the zeek server
  /// \param zeek_connection Where the connection object is stored
  /// \return A Status object
  Status initializeConnection(ZeekConnection::Ref &zeek_connection);

  /// \brief Initializes the query scheduler
  /// \param query_scheduler Where the scheduler object is stored
  /// \return A Status object
  Status initializeQueryScheduler(QueryScheduler::Ref &query_scheduler);

  /// \brief Initializes the service manager
  /// \param service_manager Where the service manager object is stored
  /// \return A Status object
  Status initializeServiceManager(IZeekServiceManager::Ref &service_manager);

  /// \brief Initializes internal tables
  Status initializeTables();

  /// \brief deinitializes internal tables
  void deinitializeTables();
};
} // namespace zeek
