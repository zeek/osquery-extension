#pragma once

#include <zeek/ivirtualtable.h>

namespace zeek {
/// \brief Provides the process_events table
class ZeekTableListTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \return A Status object
  static Status create(Ref &obj);

  /// \brief Destructor
  virtual ~ZeekTableListTablePlugin() override;

  /// \return The table name
  virtual const std::string &name() const override;

  /// \return The table schema
  virtual const Schema &schema() const override;

  /// \brief Generates the row list containing the fields from the given
  ///        configuration object
  /// \param row_list Where the generated rows are stored
  /// \return A Status object
  virtual Status generateRowList(RowList &row_list) override;

  /// \brief Updates the list of names returned by the table
  /// \param table_list Table list
  void updateTableList(const std::vector<std::string> &table_list);

protected:
  /// \brief Constructor
  ZeekTableListTablePlugin();
};
} // namespace zeek
