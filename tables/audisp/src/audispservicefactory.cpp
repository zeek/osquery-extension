#include "audispservice.h"

namespace zeek {
Status registerAudispServiceFactory(IZeekServiceManager &service_manager,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger) {

  AudispServiceFactory::Ref audisp_service_factory;
  auto status = AudispServiceFactory::create(
      audisp_service_factory, virtual_database, configuration, logger);
  if (!status.succeeded()) {
    return status;
  }

  status =
      service_manager.registerServiceFactory(std::move(audisp_service_factory));

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}
} // namespace zeek
