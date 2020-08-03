#include "fileeventstableplugin.h"

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
  event.header.file_path = "/path/to/file";

  if (type == IEndpointSecurityConsumer::Event::Type::Open) {
    event.type = type;

  } else if (type == IEndpointSecurityConsumer::Event::Type::Create) {
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

  REQUIRE(std::get<std::string>(row.at("file_path").value()) ==
          event.header.file_path);

  auto valid_event =
      event.type == IEndpointSecurityConsumer::Event::Type::Open ||
      event.type == IEndpointSecurityConsumer::Event::Type::Create;

  REQUIRE(valid_event);

  if (event.type == IEndpointSecurityConsumer::Event::Type::Open) {
    REQUIRE(std::get<std::string>(row.at("type").value()) == "open");

  } else {
    REQUIRE(std::get<std::string>(row.at("type").value()) == "create");
  }
}
} // namespace

SCENARIO("Row generation in the file_events table", "[FileEventsTablePlugin]") {

  GIVEN("a valid open EndpointSecurity event") {
    auto event = generateEvent(IEndpointSecurityConsumer::Event::Type::Open);

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, event);
      REQUIRE(status.succeeded());

      validateRow(row, event);
    }
  }

  GIVEN("a valid create EndpointSecurity event") {
    auto event = generateEvent(IEndpointSecurityConsumer::Event::Type::Create);

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, event);
      REQUIRE(status.succeeded());

      validateRow(row, event);
    }
  }
}
} // namespace zeek
