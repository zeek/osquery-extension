#include "utils.h"

#include <catch2/catch.hpp>

namespace zeek {
void validateRow(const IVirtualTable::Row &row,
                 const ExpectedValueList &expected_value_list) {

  for (const auto &expected_value : expected_value_list) {
    auto column_it = row.find(expected_value.name);
    REQUIRE(column_it != row.end());

    const auto &column_optional_value = column_it->second;

    REQUIRE(expected_value.value.has_value() ==
            column_optional_value.has_value());

    if (!expected_value.value.has_value()) {
      continue;
    }

    auto expected_variant = expected_value.value.value();

    const auto &column_variant = column_optional_value.value();

    REQUIRE(expected_variant.index() == column_variant.index());

    if (column_variant.index() == 0U) {
      const auto &table_integer_value = std::get<0U>(column_variant);
      const auto &expected_integer_value = std::get<0U>(expected_variant);

      REQUIRE(table_integer_value == expected_integer_value);

    } else {
      const auto &table_string_value = std::get<1U>(column_variant);
      const auto &expected_string_value = std::get<1U>(expected_variant);

      REQUIRE(table_string_value == expected_string_value);
    }
  }
}
} // namespace zeek