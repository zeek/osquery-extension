#include "caf/io/network/operation.hpp"

#include <string>

namespace caf {
namespace io {
namespace network {

std::string to_string(operation x) {
  switch(x) {
    default:
      return "???";
    case operation::read:
      return "read";
    case operation::write:
      return "write";
    case operation::propagate_error:
      return "propagate_error";
  };
}

} // namespace network
} // namespace io
} // namespace caf
