#include "caf/io/basp/message_type.hpp"

#include <string>

namespace caf {
namespace io {
namespace basp {

std::string to_string(message_type x) {
  switch(x) {
    default:
      return "???";
    case message_type::server_handshake:
      return "server_handshake";
    case message_type::client_handshake:
      return "client_handshake";
    case message_type::direct_message:
      return "direct_message";
    case message_type::routed_message:
      return "routed_message";
    case message_type::monitor_message:
      return "monitor_message";
    case message_type::down_message:
      return "down_message";
    case message_type::heartbeat:
      return "heartbeat";
  };
}

} // namespace basp
} // namespace io
} // namespace caf
