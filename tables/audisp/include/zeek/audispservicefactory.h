#pragma once

#include <zeek/izeekconfiguration.h>
#include <zeek/izeekservicemanager.h>

namespace zeek {
/// \brief Factory method for the AudispServiceFactory object
/// \param service_manager An initialized service manager
/// \param virtual_database The database where the Audisp table
///                         are registered
/// \param configuration An initialized configuration object
/// \param logger An initialized logger object
Status registerAudispServiceFactory(IZeekServiceManager &service_manager,
                                    IVirtualDatabase &virtual_database,
                                    IZeekConfiguration &configuration,
                                    IZeekLogger &logger);
} // namespace zeek
