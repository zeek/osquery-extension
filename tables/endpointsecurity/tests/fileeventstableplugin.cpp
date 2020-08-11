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
    FAIL("Invalid event type specified");
  }

  return event;
}

void validateRow(const IVirtualTable::Row &row,
                 const IEndpointSecurityConsumer::Event &event) {
  auto valid_event =
      event.type == IEndpointSecurityConsumer::Event::Type::Open ||
      event.type == IEndpointSecurityConsumer::Event::Type::Create;

  REQUIRE(valid_event);

  CHECK(row.size() == 13U);

  CHECK(std::get<std::int64_t>(row.at("timestamp").value()) ==
        event.header.timestamp);

  CHECK(std::get<std::int64_t>(row.at("parent_process_id").value()) ==
        event.header.parent_process_id);

  CHECK(std::get<std::int64_t>(row.at("orig_parent_process_id").value()) ==
        event.header.orig_parent_process_id);

  CHECK(std::get<std::int64_t>(row.at("process_id").value()) ==
        event.header.process_id);

  CHECK(std::get<std::int64_t>(row.at("user_id").value()) ==
        event.header.user_id);

  CHECK(std::get<std::int64_t>(row.at("group_id").value()) ==
        event.header.group_id);

  CHECK(std::get<std::int64_t>(row.at("platform_binary").value()) ==
        event.header.platform_binary);

  CHECK(std::get<std::string>(row.at("signing_id").value()) ==
        event.header.signing_id);

  CHECK(std::get<std::string>(row.at("team_id").value()) ==
        event.header.team_id);

  CHECK(std::get<std::string>(row.at("cdhash").value()) == event.header.cdhash);

  CHECK(std::get<std::string>(row.at("path").value()) == event.header.path);

  CHECK(std::get<std::string>(row.at("file_path").value()) ==
        event.header.file_path);

  if (event.type == IEndpointSecurityConsumer::Event::Type::Open) {
    CHECK(std::get<std::string>(row.at("type").value()) == "open");

  } else {
    CHECK(std::get<std::string>(row.at("type").value()) == "create");
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
