#include "caf/exit_reason.hpp"

#include <string>

namespace caf {

std::string to_string(exit_reason x) {
  switch(x) {
    default:
      return "???";
    case exit_reason::normal:
      return "normal";
    case exit_reason::unhandled_exception:
      return "unhandled_exception";
    case exit_reason::unknown:
      return "unknown";
    case exit_reason::out_of_workers:
      return "out_of_workers";
    case exit_reason::user_shutdown:
      return "user_shutdown";
    case exit_reason::kill:
      return "kill";
    case exit_reason::remote_link_unreachable:
      return "remote_link_unreachable";
    case exit_reason::unreachable:
      return "unreachable";
  };
}

} // namespace caf
