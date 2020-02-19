#include "zeektablelisttableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct ZeekTableListTablePlugin::PrivateData final {
  std::mutex table_list_mutex;
  std::vector<std::string> table_list;
};

Status ZeekTableListTablePlugin::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new ZeekTableListTablePlugin();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekTableListTablePlugin::~ZeekTableListTablePlugin() {}

const std::string &ZeekTableListTablePlugin::name() const {
  static const std::string kTableName{"zeek_table_list"};

  return kTableName;
}

const ZeekTableListTablePlugin::Schema &
ZeekTableListTablePlugin::schema() const {
  static const Schema kTableSchema = {
      {"name", IVirtualTable::ColumnType::String}};

  return kTableSchema;
}

Status ZeekTableListTablePlugin::generateRowList(RowList &row_list) {
  std::vector<std::string> table_list_copy;

  {
    std::lock_guard<std::mutex> lock(d->table_list_mutex);
    table_list_copy = d->table_list;
  }

  for (const auto &table : table_list_copy) {
    Row row = {};
    row["name"] = table;

    row_list.push_back(std::move(row));
  }

  return Status::success();
}
void ZeekTableListTablePlugin::updateTableList(
    const std::vector<std::string> &table_list) {

  {
    std::lock_guard<std::mutex> lock(d->table_list_mutex);
    d->table_list = table_list;
  }
}

ZeekTableListTablePlugin::ZeekTableListTablePlugin() : d(new PrivateData()) {}
} // namespace zeek
