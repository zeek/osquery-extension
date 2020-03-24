#include "sqlite_utils.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace zeek {
void SqliteStatementDeleter::operator()(sqlite3_stmt *obj) {
  if (obj == nullptr) {
    return;
  }

  sqlite3_finalize(obj);
}

Status prepareSqliteStatement(SqliteStatement &obj, sqlite3 *database,
                              const std::string &query) {
  obj.reset();

  sqlite3_stmt *sql_stmt{nullptr};
  auto err =
      sqlite3_prepare_v2(database, query.c_str(),
                         static_cast<int>(query.size()), &sql_stmt, nullptr);

  if (err != SQLITE_OK) {
    return Status::failure("Failed to prepare the SQLite statement");
  }

  obj.reset(sql_stmt);
  return Status::success();
}

Status validateSqliteName(const std::string &name) {
  static const auto kSyntaxError =
      Status::failure("Names must start with a letter and can only contain "
                      "underscores and alphanumeric characters");

  if (name.empty()) {
    return kSyntaxError;
  }

  if (std::isalpha(name[0]) == 0) {
    return kSyntaxError;
  }

  // clang-format off
  auto it = std::find_if(
    name.begin(),
    name.end(),

    [](const char &c) -> bool {
      auto character = static_cast<char>(c);

      if (character == '_') {
        return false;
      }

      return (std::isalnum(character) == 0);
    }
  );
  // clang-format on

  if (it != name.end()) {
    return kSyntaxError;
  }

  return Status::success();
}

Status allocateSqliteMemory(Sqlite3MemoryRef &obj, std::size_t size) {
  obj.reset();

  auto ptr = sqlite3_malloc(static_cast<int>(size));
  if (ptr == nullptr) {
    return Status::failure("Memory allocation failure");
  }

  std::memset(ptr, 0, size);

  obj.reset(ptr);
  return Status::success();
}
} // namespace zeek
