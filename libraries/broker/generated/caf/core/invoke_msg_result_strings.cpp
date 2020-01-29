#include "caf/invoke_message_result.hpp"

#include <string>

namespace caf {

std::string to_string(invoke_message_result x) {
  switch(x) {
    default:
      return "???";
    case invoke_message_result::consumed:
      return "consumed";
    case invoke_message_result::skipped:
      return "skipped";
    case invoke_message_result::dropped:
      return "dropped";
  };
}

} // namespace caf
