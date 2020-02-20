#pragma once

#include <zeek/ivirtualtable.h>

namespace zeek {
/// \brief Provides the host_information table
class IHostInformationTablePlugin : public IVirtualTable {
public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \return A Status object
  static Status create(Ref &obj);

  /// \brief Constructor
  IHostInformationTablePlugin() = default;

  /// \brief Destructor
  virtual ~IHostInformationTablePlugin() override = default;
};
} // namespace zeek
