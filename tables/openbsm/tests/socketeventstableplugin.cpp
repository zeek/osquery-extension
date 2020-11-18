#include "socketeventstableplugin.h"

#include <catch2/catch.hpp>

namespace zeek {
namespace {
IOpenbsmConsumer::Event generateEvent(IOpenbsmConsumer::Event::Type type) {
  IOpenbsmConsumer::Event event;
  event.header.timestamp = 1U;
  event.header.process_id = 2U;
  event.header.user_id = 3U;
  event.header.group_id = 4U;
  event.header.path = "/path/to/application";
  event.header.success = 1;
  event.header.family = 2;

  if (type == IOpenbsmConsumer::Event::Type::Bind) {
    event.type = type;
    event.header.remote_address = "";
    event.header.remote_port = 0;

    event.header.local_address = "192.168.1.1";
    event.header.local_port = 9876;

  } else if (type == IOpenbsmConsumer::Event::Type::Connect) {
    event.type = type;

    event.header.local_address = "";
    event.header.local_port = 0;

    event.header.remote_address = "192.168.1.1";
    event.header.remote_port = 9876;

  } else {
    FAIL("Invalid event type specified");
  }

  return event;
}

void validateRow(const IVirtualTable::Row &row,
                 const IOpenbsmConsumer::Event &event) {

  auto valid_event = event.type == IOpenbsmConsumer::Event::Type::Bind ||
                     event.type == IOpenbsmConsumer::Event::Type::Connect;

  REQUIRE(valid_event);

  CHECK(row.size() == 12U);

  CHECK(std::get<std::int64_t>(row.at("timestamp").value()) ==
        event.header.timestamp);

  CHECK(std::get<std::int64_t>(row.at("process_id").value()) ==
        event.header.process_id);

  CHECK(std::get<std::int64_t>(row.at("user_id").value()) ==
        event.header.user_id);

  CHECK(std::get<std::int64_t>(row.at("group_id").value()) ==
        event.header.group_id);

  CHECK(std::get<std::string>(row.at("path").value()) == event.header.path);

  CHECK(std::get<std::int64_t>(row.at("success").value()) ==
        event.header.success);

  CHECK(std::get<std::int64_t>(row.at("family").value()) ==
        event.header.family);

  CHECK(std::get<std::string>(row.at("remote_address").value()) ==
        event.header.remote_address);

  CHECK(std::get<std::int64_t>(row.at("remote_port").value()) ==
        event.header.remote_port);

  CHECK(std::get<std::string>(row.at("local_address").value()) ==
        event.header.local_address);

  CHECK(std::get<std::int64_t>(row.at("local_port").value()) ==
        event.header.local_port);

  if (event.type == IOpenbsmConsumer::Event::Type::Bind) {
    CHECK(std::get<std::string>(row.at("type").value()) == "bind");

  } else {
    CHECK(std::get<std::string>(row.at("type").value()) == "connect");
  }
}
} // namespace

SCENARIO("Row generation in the socket_events table",
         "[SocketEventsTablePlugin]") {

  GIVEN("a valid bind OpenBSM event") {
    auto event = generateEvent(IOpenbsmConsumer::Event::Type::Bind);

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = SocketEventsTablePlugin::generateRow(row, event);
      CHECK(status.succeeded());

      validateRow(row, event);
    }
  }

  GIVEN("a valid Connect OpenBSM event") {
    auto event = generateEvent(IOpenbsmConsumer::Event::Type::Connect);

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = SocketEventsTablePlugin::generateRow(row, event);
      CHECK(status.succeeded());

      validateRow(row, event);
    }
  }
}
} // namespace zeek
