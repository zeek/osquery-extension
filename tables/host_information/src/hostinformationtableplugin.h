#pragma once

#include <zeek/ihostinformationtableplugin.h>

namespace zeek {
/// \brief Provides the host_information table
class HostInformationTablePlugin final : public IHostInformationTablePlugin {
public:
  /// \brief Destructor
  virtual ~HostInformationTablePlugin() override;

  /// \return The table name
  virtual const std::string &name() const override;

  /// \return The table schema
  virtual const Schema &schema() const override;

  /// \brief Generates the row list containing the fields from the given
  ///        configuration object
  /// \param row_list Where the generated rows are stored
  /// \return A Status object
  virtual Status generateRowList(RowList &row_list) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Constructor
  HostInformationTablePlugin();

  friend class IHostInformationTablePlugin;
};
} // namespace zeek
