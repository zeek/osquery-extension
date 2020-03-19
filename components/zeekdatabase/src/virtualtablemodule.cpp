#include "virtualtablemodule.h"
#include "sqlite_utils.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <type_traits>

namespace zeek {
namespace {
struct VirtualTableSession final {
  IVirtualTable::RowList row_list;
  std::size_t current_row{0U};
};

struct VirtualTableCursor final {
  struct sqlite3_vtab_cursor base_cursor;
  VirtualTableSession *session;
};

struct VirtualTableInstance final {
  struct sqlite3_vtab base_vtab;
  VirtualTableModule *module_instance;
  std::size_t column_count{0U};
};

// clang-format off
static_assert(
  std::is_standard_layout<VirtualTableCursor>::value &&
  std::is_trivially_copyable<VirtualTableCursor>::value,

  "VirtualTableCursor must be a POD type"
);
// clang-format on

// clang-format off
static_assert(
  std::is_standard_layout<VirtualTableInstance>::value &&
  std::is_trivially_copyable<VirtualTableInstance>::value,

  "VirtualTableInstance must be a POD type"
);
// clang-format on

int xBestIndexCallback(sqlite3_vtab *, sqlite3_index_info *) {
  return SQLITE_OK;
}

// clang-format off
static const struct sqlite3_module kSqliteModule = {
  // Version
  3,

  // Mandatory callbacks; enough to get read-only tables
  &VirtualTableModule::onTableCreate,
  &VirtualTableModule::onTableCreate,
  xBestIndexCallback,
  &VirtualTableModule::onTableDisconnect,
  &VirtualTableModule::onTableDisconnect,
  &VirtualTableModule::onTableOpen,
  &VirtualTableModule::onTableClose,
  &VirtualTableModule::onTableFilter,
  &VirtualTableModule::onTableNext,
  &VirtualTableModule::onTableEof,
  &VirtualTableModule::onTableColumn,
  &VirtualTableModule::onTableRowid,

  // Unused callbacks
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr,
  nullptr
};
// clang-format on
} // namespace

struct VirtualTableModule::PrivateData final {
  IVirtualTable::Ref table;
  VirtualTableInstance *table_instance{nullptr};
};

Status VirtualTableModule::create(Ref &obj, IVirtualTable::Ref table) {
  obj.reset();

  try {
    auto ptr = new VirtualTableModule(table);
    table = {};

    obj.reset(ptr);
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

VirtualTableModule::~VirtualTableModule() {}

const std::string &VirtualTableModule::name() const { return d->table->name(); }

const struct sqlite3_module *VirtualTableModule::sqliteModule() {
  return &kSqliteModule;
}

int VirtualTableModule::onTableCreate(sqlite3 *sqlite_database,
                                      void *virtual_table_module_ptr, int,
                                      const char *const *,
                                      sqlite3_vtab **table_instance, char **) {

  // Return the table instance to sqlite
  auto &instance =
      *reinterpret_cast<VirtualTableModule *>(virtual_table_module_ptr);

  auto &instance_data = *instance.d.get();

  try {
    instance_data.table_instance = new VirtualTableInstance();
    instance_data.table_instance->module_instance = &instance;
    instance_data.table_instance->column_count =
        instance_data.table->schema().size();

    *table_instance = &instance_data.table_instance->base_vtab;

  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  }

  // Generate the CREATE TABLE statement and declare the virtual table
  // within sqlite
  std::string create_table_stmt;
  auto status =
      generateSQLTableDefinition(create_table_stmt, instance_data.table);

  if (!status.succeeded()) {
    return SQLITE_ERROR;
  }

  auto err = sqlite3_declare_vtab(sqlite_database, create_table_stmt.c_str());
  if (err != SQLITE_OK) {
    return err;
  }

  return SQLITE_OK;
}

int VirtualTableModule::onTableOpen(sqlite3_vtab *table_instance,
                                    sqlite3_vtab_cursor **cursor) {

  try {
    // Create a new cursor
    Sqlite3MemoryRef cursor_memory;
    auto status =
        allocateSqliteMemory(cursor_memory, sizeof(VirtualTableCursor));

    if (!status.succeeded()) {
      return SQLITE_NOMEM;
    }

    // Initialize a new session; we are using a raw pointer because we want to
    // keep the cursor as a POD type
    auto &cursor_impl = *static_cast<VirtualTableCursor *>(cursor_memory.get());
    cursor_impl.session = new VirtualTableSession();
    cursor_impl.session->current_row = 0U;

    // Generate the row list from the table plugin
    auto &table_instance_impl =
        *reinterpret_cast<VirtualTableInstance *>(table_instance);

    auto &module_instance_data = *table_instance_impl.module_instance->d.get();
    auto &table = *module_instance_data.table.get();

    status = table.generateRowList(cursor_impl.session->row_list);
    if (!status.succeeded()) {
      return SQLITE_ERROR;
    }

    auto &instance = *reinterpret_cast<VirtualTableInstance *>(table_instance);

    for (const auto &row : cursor_impl.session->row_list) {
      if (row.size() != instance.column_count) {
        std::cerr << "Invalid column count returned by table implementation\n";
        return SQLITE_ERROR;
      }
    }

    // Return the cursor to sqlite
    *cursor = reinterpret_cast<sqlite3_vtab_cursor *>(cursor_memory.release());
    return SQLITE_OK;

  } catch (const std::bad_alloc &) {
    return SQLITE_NOMEM;
  }
}

int VirtualTableModule::onTableDisconnect(sqlite3_vtab *table_instance) {
  if (table_instance != nullptr) {
    auto instance = reinterpret_cast<VirtualTableInstance *>(table_instance);
    delete instance;
  }

  return SQLITE_OK;
}

int VirtualTableModule::onTableClose(sqlite3_vtab_cursor *cursor) {
  auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);

  delete cursor_impl.session;
  sqlite3_free(cursor);

  return SQLITE_OK;
}

int VirtualTableModule::onTableEof(sqlite3_vtab_cursor *cursor) {
  const auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);
  const auto &session = *cursor_impl.session;

  if (session.current_row >= session.row_list.size()) {
    return 1;
  }

  return 0;
}

int VirtualTableModule::onTableFilter(sqlite3_vtab_cursor *cursor, int,
                                      const char *, int, sqlite3_value **) {
  auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);
  auto &session = *cursor_impl.session;

  session.current_row = 0U;
  return SQLITE_OK;
}

int VirtualTableModule::onTableNext(sqlite3_vtab_cursor *cursor) {
  auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);
  auto &session = *cursor_impl.session;

  ++session.current_row;
  return SQLITE_OK;
}

int VirtualTableModule::onTableColumn(sqlite3_vtab_cursor *cursor,
                                      sqlite3_context *context, int i) {

  auto &instance = *reinterpret_cast<VirtualTableInstance *>(cursor->pVtab);
  if (static_cast<std::size_t>(i) >= instance.column_count) {
    std::cerr << "Invalid column index\n";
    return SQLITE_ERROR;
  }

  auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);
  auto &session = *cursor_impl.session;

  auto &current_row = session.row_list.at(session.current_row);
  auto current_column_it = std::next(current_row.begin(), i);

  auto &current_column = *current_column_it;

  auto &current_column_value = current_column.second;
  if (!current_column_value.has_value()) {
    sqlite3_result_null(context);
    return SQLITE_OK;
  }

  const auto &current_column_value_data = current_column_value.value();

  if (std::holds_alternative<std::int64_t>(current_column_value_data)) {
    const auto &current_column_data =
        std::get<std::int64_t>(current_column_value_data);

    sqlite3_result_int(context, static_cast<int>(current_column_data));

  } else if (std::holds_alternative<std::string>(current_column_value_data)) {
    const auto &current_column_data =
        std::get<std::string>(current_column_value_data);

    sqlite3_result_text(context, current_column_data.c_str(),
                        static_cast<int>(current_column_data.size()),
                        SQLITE_STATIC);

  } else if (std::holds_alternative<double>(current_column_value_data)) {
    const auto &current_column_data =
        std::get<double>(current_column_value_data);

    sqlite3_result_double(context, current_column_data);

  } else {
    std::cerr << "Invalid column type\n";
    return SQLITE_ERROR;
  }

  return SQLITE_OK;
}

int VirtualTableModule::onTableRowid(sqlite3_vtab_cursor *cursor,
                                     sqlite3_int64 *rowid) {

  // It is mandatory to define this callback in the SQLite module, but it is
  // actually never used since our tables are created with the "WITHOUT ROWID"
  // directive

  const auto &cursor_impl = *reinterpret_cast<VirtualTableCursor *>(cursor);
  const auto &session = *cursor_impl.session;

  *rowid = session.current_row + 1;
  return SQLITE_OK;
}

Status
VirtualTableModule::generateSQLTableDefinition(std::string &sql_statement,
                                               IVirtualTable::Ref table) {

  sql_statement = {};

  const auto &name = table->name();
  const auto &schema = table->schema();

  std::stringstream buffer;
  buffer << "CREATE TABLE " << name << " (\n";

  for (auto it = schema.begin(); it != schema.end(); ++it) {
    const auto &column_name = it->first;
    const auto &column_type = it->second;

    const char *column_type_as_string = nullptr;

    switch (column_type) {
    case IVirtualTable::ColumnType::Integer:
      column_type_as_string = "BIGINT";
      break;

    case IVirtualTable::ColumnType::String:
      column_type_as_string = "TEXT";
      break;

    default:
      break;
    }

    if (column_type_as_string == nullptr) {
      return Status::failure("Invalid column type");
    }

    buffer << "  " << column_name << " " << column_type_as_string;

    if (std::next(it, 1) != schema.end()) {
      buffer << ",";
    }

    buffer << "\n";
  }

  buffer << ")\n";

  sql_statement = buffer.str();
  return Status::success();
}

VirtualTableModule::VirtualTableModule(IVirtualTable::Ref table)
    : d(new PrivateData) {

  d->table = table;
}
} // namespace zeek
