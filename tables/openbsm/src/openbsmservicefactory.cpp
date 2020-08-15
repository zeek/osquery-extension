#include "openbsmservice.h"

namespace zeek {
Status registerOpenbsmServiceFactory(IZeekServiceManager &service_manager,
                                     IVirtualDatabase &virtual_database,
                                     IZeekConfiguration &configuration,
                                     IZeekLogger &logger) {

  OpenbsmServiceFactory::Ref openbsm_service_factory;
  auto status = OpenbsmServiceFactory::create(
      openbsm_service_factory, virtual_database, configuration, logger);

  if (!status.succeeded()) {
    return status;
  }

  status = service_manager.registerServiceFactory(
      std::move(openbsm_service_factory));

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}
} // namespace zeek
