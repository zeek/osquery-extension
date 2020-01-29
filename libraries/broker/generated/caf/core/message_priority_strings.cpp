#include "caf/message_priority.hpp"

#include <string>

namespace caf {

std::string to_string(message_priority x) {
  switch(x) {
    default:
      return "???";
    case message_priority::high:
      return "high";
    case message_priority::normal:
      return "normal";
  };
}

} // namespace caf
