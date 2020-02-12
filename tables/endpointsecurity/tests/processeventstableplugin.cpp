#include "processeventstableplugin.h"

#include <catch2/catch.hpp>

namespace zeek {
namespace {
IEndpointSecurityConsumer::Event
generateEvent(IEndpointSecurityConsumer::Event::Type type) {
  IEndpointSecurityConsumer::Event event;
  event.header.timestamp = 1U;
  event.header.parent_process_id = 2U;
  event.header.orig_parent_process_id = 3U;
  event.header.process_id = 4U;
  event.header.user_id = 5U;
  event.header.group_id = 6U;
  event.header.platform_binary = true;
  event.header.signing_id = "SigningID";
  event.header.team_id = "TeamID";
  event.header.cdhash = "12345";
  event.header.path = "/path/to/application";

  if (type == IEndpointSecurityConsumer::Event::Type::Exec) {
    event.type = type;

    IEndpointSecurityConsumer::Event::ExecEventData exec_data;
    exec_data.argument_list.push_back("argument1");
    exec_data.argument_list.push_back("argument2");

    event.opt_exec_event_data = std::move(exec_data);

  } else if (type == IEndpointSecurityConsumer::Event::Type::Fork) {
    event.type = type;

  } else {
    throw std::logic_error("Invalid event type specified");
  }

  return event;
}

void validateRow(const IVirtualTable::Row &row,
                 const IEndpointSecurityConsumer::Event &event) {
  REQUIRE(row.size() == 13U);

  REQUIRE(std::get<std::int64_t>(row.at("timestamp").value()) ==
          event.header.timestamp);

  REQUIRE(std::get<std::int64_t>(row.at("parent_process_id").value()) ==
          event.header.parent_process_id);

  REQUIRE(std::get<std::int64_t>(row.at("orig_parent_process_id").value()) ==
          event.header.orig_parent_process_id);

  REQUIRE(std::get<std::int64_t>(row.at("process_id").value()) ==
          event.header.process_id);

  REQUIRE(std::get<std::int64_t>(row.at("user_id").value()) ==
          event.header.user_id);

  REQUIRE(std::get<std::int64_t>(row.at("group_id").value()) ==
          event.header.group_id);

  REQUIRE(std::get<std::int64_t>(row.at("platform_binary").value()) ==
          event.header.platform_binary);

  REQUIRE(std::get<std::string>(row.at("signing_id").value()) ==
          event.header.signing_id);

  REQUIRE(std::get<std::string>(row.at("team_id").value()) ==
          event.header.team_id);

  REQUIRE(std::get<std::string>(row.at("cdhash").value()) ==
          event.header.cdhash);

  REQUIRE(std::get<std::string>(row.at("path").value()) == event.header.path);

  auto valid_event =
      event.type == IEndpointSecurityConsumer::Event::Type::Exec ||
      event.type == IEndpointSecurityConsumer::Event::Type::Fork;

  REQUIRE(valid_event);

  if (event.type == IEndpointSecurityConsumer::Event::Type::Exec) {
    REQUIRE(std::get<std::string>(row.at("type").value()) == "exec");

    std::string expected_cmd_line;
    for (const auto &arg : event.opt_exec_event_data.value().argument_list) {
      expected_cmd_line += " " + arg;
    }

    REQUIRE(std::get<std::string>(row.at("cmdline").value()) ==
            expected_cmd_line);

  } else {
    REQUIRE(std::get<std::string>(row.at("type").value()) == "fork");
  }
}
} // namespace

SCENARIO("Row generation in the process_events table",
         "[ProcessEventsTablePlugin]") {

  GIVEN("a valid exec EndpointSecurity event") {
    auto event = generateEvent(IEndpointSecurityConsumer::Event::Type::Exec);

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = ProcessEventsTablePlugin::generateRow(row, event);
      REQUIRE(status.succeeded());

      validateRow(row, event);
    }
  }

  GIVEN("a valid fork EndpointSecurity event") {
    auto event = generateEvent(IEndpointSecurityConsumer::Event::Type::Fork);

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = ProcessEventsTablePlugin::generateRow(row, event);
      REQUIRE(status.succeeded());

      validateRow(row, event);
    }
  }
}
} // namespace zeek
