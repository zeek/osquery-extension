#pragma once

#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>
#include <zeek/izeekservicemanager.h>

namespace zeek {
/// \brief An Zeek service that acts as Audit event publisher
///        using Audisp
class AudispService final : public IZeekService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Destructor
  virtual ~AudispService() override;

  /// \return The service name
  virtual const std::string &name() const override;

  /// \brief Starts the service until it is interrupted
  /// \param terminate Set to true when the service should terminate
  /// \return A Status object
  virtual Status exec(std::atomic_bool &terminate) override;

  AudispService(const AudispService &) = delete;
  AudispService &operator=(const AudispService &) = delete;

protected:
  /// \brief Constructor
  /// \param virtual_database The database where the Audisp table
  ///                         are registered
  /// \param configuration An initialized configuration object
  /// \param logger An initialized logger object
  AudispService(IVirtualDatabase &virtual_database,
                IZeekConfiguration &configuration, IZeekLogger &logger);

  friend class AudispServiceFactory;
};

/// \brief The factort for the Audisp service
class AudispServiceFactory final : public IZeekServiceFactory {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the new object is stored
  /// \param virtual_database The database where the Audisp table
  ///                         are registered
  /// \param configuration An initialized configuration object
  /// \param logger An initialized logger object
  static Status create(Ref &obj, IVirtualDatabase &virtual_database,
                       IZeekConfiguration &configuration, IZeekLogger &logger);

  /// \brief Destructor
  virtual ~AudispServiceFactory() override;

  /// \return The service factory name
  virtual const std::string &name() const override;

  /// \brief Creates a new Audisp service
  /// \param obj Where the created object is stored
  /// \return A Status object
  virtual Status spawn(IZeekService::Ref &obj) override;

protected:
  /// \brief Constructor
  /// \param configuration An initialized configuration object
  /// \param logger An initialized logger object
  AudispServiceFactory(IVirtualDatabase &virtual_database,
                       IZeekConfiguration &configuration, IZeekLogger &logger);
};
} // namespace zeek
