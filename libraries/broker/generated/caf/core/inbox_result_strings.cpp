#include "caf/intrusive/inbox_result.hpp"

#include <string>

namespace caf {
namespace intrusive {

std::string to_string(inbox_result x) {
  switch(x) {
    default:
      return "???";
    case inbox_result::success:
      return "success";
    case inbox_result::unblocked_reader:
      return "unblocked_reader";
    case inbox_result::queue_closed:
      return "queue_closed";
  };
}

} // namespace intrusive
} // namespace caf
