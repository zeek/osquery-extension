#include "virtualdatabase.h"
#include "testtable.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Basic VirtualDatabase operations", "[VirtualDatabase]") {
  GIVEN("a virtual database") {
    IVirtualDatabase::Ref virtual_database;
    auto status = IVirtualDatabase::create(virtual_database);
    REQUIRE(status.succeeded());

    WHEN("registering a new table plugin") {
      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid));

      status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      THEN("the new virtual table can be queried") {
        IVirtualDatabase::QueryOutput query_output;
        status = virtual_database->query(query_output, "SELECT * FROM TestTable;");

        REQUIRE(status.succeeded());
        REQUIRE(!query_output.empty());
      }
    }

    WHEN("registering the same table twice") {
      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid));

      status = virtual_database->registerTable(test_table);

      REQUIRE(status.succeeded());

      {
        IVirtualTable::Ref test_table2(
            new TestTable(TestTable::SchemaType::Valid));

        status = virtual_database->registerTable(test_table2);
      }

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }

    WHEN("registering a table with an invalid schema") {
      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Invalid));

      status = virtual_database->registerTable(test_table);

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }

    WHEN("querying an invalid table") {
      IVirtualDatabase::QueryOutput query_output;

      // clang-format off
      query_output.push_back(
        {
          { "column1", "dummy_value" },
          { "column2", "dummy_value2" }
        }
      );
      // clang-format on

      status = virtual_database->query(query_output,
                                            "SELECT * FROM InvalidTableName;");

      THEN("an error is generated and no output is returned") {
        REQUIRE(!status.succeeded());
        REQUIRE(query_output.empty());
      }
    }

    WHEN("querying a table with multiple rows") {
      static const std::size_t kRowCount{100U};

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid, kRowCount));

      status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      IVirtualDatabase::QueryOutput query_output;
      status = virtual_database->query(
          query_output, "SELECT integer, string FROM TestTable;");

      THEN("the correct rows are returned") {
        REQUIRE(status.succeeded());
        REQUIRE(query_output.size() == kRowCount);

        for (std::size_t i = 0U; i < query_output.size(); ++i) {
          const auto &current_row = query_output.at(i);
          REQUIRE(current_row.size() == 2U);

          const auto &integer_column = current_row.at(0U);
          REQUIRE(integer_column.name == "integer");
          REQUIRE(integer_column.data.has_value());

          auto variant_value = integer_column.data.value();
          REQUIRE(std::holds_alternative<std::int64_t>(variant_value));

          auto integer_value = std::get<std::int64_t>(variant_value);
          CHECK(integer_value == static_cast<std::int64_t>(i));

          const auto &string_column = current_row.at(1U);
          REQUIRE(string_column.name == "string");
          REQUIRE(string_column.data.has_value());

          variant_value = string_column.data.value();
          REQUIRE(std::holds_alternative<std::string>(variant_value));

          auto string_value = std::get<std::string>(variant_value);
          CHECK(string_value == std::to_string(i));
        }
      }
    }

    WHEN("querying an empty table") {
      static const std::size_t kRowCount{0U};

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid, kRowCount));

      status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      IVirtualDatabase::QueryOutput query_output;
      status =
          virtual_database->query(query_output, "SELECT * FROM TestTable;");

      THEN("no rows are returned") {
        REQUIRE(status.succeeded());
        REQUIRE(query_output.size() == kRowCount);
      }
    }
  }
}

SCENARIO("VirtualDatabase utilities", "[VirtualDatabase]") {
  GIVEN("an invalid schema") {
    TestTable invalid_table(TestTable::SchemaType::Invalid);

    WHEN("validating column types and names") {
      auto status = VirtualDatabase::validateTableSchema(invalid_table.schema());

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }
  }

  GIVEN("a valid schema") {
    TestTable valid_table(TestTable::SchemaType::Valid);

    WHEN("validating column types and names") {
      auto status = VirtualDatabase::validateTableSchema(valid_table.schema());

      THEN("success is returned") { REQUIRE(status.succeeded()); }
    }
  }

  GIVEN("an invalid table name") {
    static const std::vector<std::string> kInvalidTableNameList = {
        "", "0_invalid_name", "invalid name"};

    WHEN("validating the name") {
      std::vector<Status> status_list;

      for (const auto &table_name : kInvalidTableNameList) {
        auto status = VirtualDatabase::validateTableName(table_name);
        status_list.push_back(status);
      }

      THEN("the name is rejected") {
        for (const auto &status : status_list) {
          REQUIRE(!status.succeeded());
        }
      }
    }
  }
}
} // namespace zeek
