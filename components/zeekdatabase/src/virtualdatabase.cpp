#include "virtualdatabase.h"
#include "sqlite_utils.h"
#include "virtualtablemodule.h"
#include "zeektablelisttableplugin.h"

#include <unordered_map>
#include <unordered_set>

#include <sqlite3.h>

namespace zeek {
struct VirtualDatabase::PrivateData final {
  sqlite3 *sqlite_database{nullptr};

  std::unordered_map<std::string, VirtualTableModule::Ref>
      registered_module_list;

  IVirtualTable::Ref zeek_table_list_table_plugin;
};

VirtualDatabase::~VirtualDatabase() {
  unregisterTable("zeek_table_list");

  sqlite3_close(d->sqlite_database);
  d->sqlite_database = nullptr;
}

std::vector<std::string> VirtualDatabase::virtualTableList() const {
  std::vector<std::string> virtual_table_list;

  for (const auto &p : d->registered_module_list) {
    const auto &name = p.first;
    virtual_table_list.push_back(name);
  }

  return virtual_table_list;
}

Status VirtualDatabase::registerTable(IVirtualTable::Ref table) {
  if (table->name().empty()) {
    return Status::failure("Empty table name");
  }

  if (d->registered_module_list.count(table->name()) != 0U) {
    return Status::failure("A table with the same is already registered");
  }

  auto status = validateTableSchema(table->schema());
  if (!status.succeeded()) {
    return status;
  }

  VirtualTableModule::Ref virtual_table_module;
  status = VirtualTableModule::create(virtual_table_module, table);

  if (!status.succeeded()) {
    return status;
  }

  table = {};

  auto err = sqlite3_create_module_v2(d->sqlite_database,
                                      virtual_table_module->name().c_str(),
                                      virtual_table_module->sqliteModule(),
                                      virtual_table_module.get(), nullptr);

  if (err != SQLITE_OK) {
    return Status::failure(
        "Failed to create the SQLite module for the virtual table");
  }

  auto table_name = virtual_table_module->name();

  d->registered_module_list.insert(
      {table_name, std::move(virtual_table_module)});

  auto &zeek_table_list_plugin = *static_cast<ZeekTableListTablePlugin *>(
      d->zeek_table_list_table_plugin.get());

  zeek_table_list_plugin.updateTableList(virtualTableList());

  return Status::success();
}

Status VirtualDatabase::unregisterTable(const std::string &name) {
  auto table_it = d->registered_module_list.find(name);
  if (table_it == d->registered_module_list.end()) {
    return Status::failure("The specified table does not exists");
  }

  std::vector<std::string> module_list;
  module_list.reserve(d->registered_module_list.size());

  std::vector<const char *> string_pointer_list;

  for (const auto &p : d->registered_module_list) {
    const auto &module_name = p.first;

    if (name == module_name) {
      continue;
    }

    module_list.push_back(module_name);

    const auto &last_element = module_list.back();
    string_pointer_list.push_back(last_element.c_str());
  }

  string_pointer_list.push_back(nullptr);
  if (sqlite3_drop_modules(d->sqlite_database, string_pointer_list.data()) !=
      SQLITE_OK) {
    return Status::failure("Failed to unregister the table");
  }

  d->registered_module_list.erase(table_it);

  auto &zeek_table_list_plugin = *static_cast<ZeekTableListTablePlugin *>(
      d->zeek_table_list_table_plugin.get());

  zeek_table_list_plugin.updateTableList(virtualTableList());

  return Status::success();
}

Status VirtualDatabase::query(QueryOutput &output,
                              const std::string &query) const {

  output = {};

  SqliteStatement sql_stmt;
  auto status = prepareSqliteStatement(sql_stmt, d->sqlite_database, query);
  if (!status.succeeded()) {
    return status;
  }

  if (!status.succeeded()) {
    return status;
  }

  QueryOutput temp_output;
  auto column_count = sqlite3_column_count(sql_stmt.get());

  while (sqlite3_step(sql_stmt.get()) == SQLITE_ROW) {
    OutputRow current_row = {};

    for (int column_index = 0; column_index < column_count; ++column_index) {
      ColumnValue column = {};

      auto sqlite_type = sqlite3_column_type(sql_stmt.get(), column_index);

      switch (sqlite_type) {
      case SQLITE_NULL:
        break;

      case SQLITE_INTEGER:
        column.data = static_cast<std::int64_t>(
            sqlite3_column_int(sql_stmt.get(), column_index));

        break;

      case SQLITE_TEXT: {
        auto string_data = reinterpret_cast<const char *>(
            sqlite3_column_text(sql_stmt.get(), column_index));

        column.data = std::string(string_data);
        break;
      }

      default:
        return Status::failure("Invalid column type found");
      }

      column.name = sqlite3_column_name(sql_stmt.get(), column_index);

      current_row.push_back(std::move(column));
    }

    temp_output.push_back(std::move(current_row));
  }

  output = std::move(temp_output);
  return Status::success();
}

VirtualDatabase::VirtualDatabase() : d(new PrivateData) {
  if (sqlite3_open(":memory:", &d->sqlite_database) != SQLITE_OK) {
    throw Status::failure("Failed to create the SQLite database");
  }

  auto status =
      ZeekTableListTablePlugin::create(d->zeek_table_list_table_plugin);

  if (!status.succeeded()) {
    throw status;
  }

  status = registerTable(d->zeek_table_list_table_plugin);
  if (!status.succeeded()) {
    throw status;
  }
}

Status VirtualDatabase::validateTableName(const std::string &name) {
  return validateSqliteName(name);
}

Status
VirtualDatabase::validateTableSchema(const IVirtualTable::Schema &schema) {
  static const std::unordered_set<IVirtualTable::ColumnType> kValidColumnTypes =
      {IVirtualTable::ColumnType::Integer, IVirtualTable::ColumnType::String,
       IVirtualTable::ColumnType::Double};

  if (schema.empty()) {
    return Status::failure("Table schema is empty");
  }

  for (const auto &p : schema) {
    const auto &column_name = p.first;
    const auto &column_type = p.second;

    if (kValidColumnTypes.count(column_type) == 0U) {
      return Status::failure("Invalid column type encountered");
    }

    auto status = validateSqliteName(column_name);
    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

Status IVirtualDatabase::create(IVirtualDatabase::Ref &obj) {
  obj.reset();

  try {
    auto ptr = new VirtualDatabase;
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
