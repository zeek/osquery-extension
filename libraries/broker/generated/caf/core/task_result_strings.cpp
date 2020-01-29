#include "caf/intrusive/task_result.hpp"

#include <string>

namespace caf {
namespace intrusive {

std::string to_string(task_result x) {
  switch(x) {
    default:
      return "???";
    case task_result::resume:
      return "resume";
    case task_result::skip:
      return "skip";
    case task_result::stop:
      return "stop";
    case task_result::stop_all:
      return "stop_all";
  };
}

} // namespace intrusive
} // namespace caf
