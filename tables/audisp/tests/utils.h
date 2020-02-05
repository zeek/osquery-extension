#include <string>
#include <vector>

#include <zeek/ivirtualtable.h>

namespace zeek {
struct ExpectedValue final {
  std::string name;
  IVirtualTable::OptionalVariant value;
};

using ExpectedValueList = std::vector<ExpectedValue>;

void validateRow(const IVirtualTable::Row &row,
                 const ExpectedValueList &expected_value_list);
} // namespace zeek
