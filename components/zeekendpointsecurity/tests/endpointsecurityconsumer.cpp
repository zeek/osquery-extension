#include "endpointsecurityconsumer.h"

#include <iostream>

#include <catch2/catch.hpp>

#include <EndpointSecurity/EndpointSecurity.h>

namespace zeek {
TEST_CASE("Event header initialization for Exec Event",
          "[ZeekEndpointConsumer]") {
  es_process_t process = {};
  process.ppid = 10U;
  process.original_ppid = 11U;

  for (auto i = 0U; i < 8U; ++i) {
    process.audit_token.val[i] = 0xF0U + i;
  }

  process.is_platform_binary = 1U;

  for (auto i = 0U; i < sizeof(process.cdhash); ++i) {
    process.cdhash[i] = 0xA0U + i;
  }

  const char *kDummySigningIdentifier = "SigningID";
  process.signing_id.data = kDummySigningIdentifier;
  process.signing_id.length = std::strlen(kDummySigningIdentifier);

  const char *kDummyTeamIdentifier = "TeamID";
  process.team_id.data = kDummyTeamIdentifier;
  process.team_id.length = std::strlen(kDummyTeamIdentifier);

  const char *kDummyPath = "/path/to/application";
  es_file_t executable = {};
  executable.path.data = kDummyPath;
  executable.path.length = std::strlen(kDummyPath);

  process.executable = &executable;

  es_message_t es_message = {};
  es_message.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
  es_message.event.exec.target = &process;

  IEndpointSecurityConsumer::Event::Header header;
  auto status =
      EndpointSecurityConsumer::initializeEventHeader(header, es_message);

  REQUIRE(status.succeeded());

  CHECK(header.timestamp != 0U);
  CHECK(header.parent_process_id == 10U);
  CHECK(header.orig_parent_process_id == 11U);
  CHECK(header.process_id == 245U);
  CHECK(header.user_id == 241U);
  CHECK(header.group_id == 242U);
  CHECK(header.platform_binary == 1U);
  CHECK(header.signing_id == kDummySigningIdentifier);
  CHECK(header.team_id == kDummyTeamIdentifier);
  CHECK(header.path == kDummyPath);
  CHECK(header.cdhash == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
}

TEST_CASE("Event header initialization for Open event",
          "[ZeekEndpointConsumer]") {
  es_process_t process = {};
  process.ppid = 10U;
  process.original_ppid = 11U;

  for (auto i = 0U; i < 8U; ++i) {
    process.audit_token.val[i] = 0xF0U + i;
  }

  process.is_platform_binary = 1U;

  for (auto i = 0U; i < sizeof(process.cdhash); ++i) {
    process.cdhash[i] = 0xA0U + i;
  }

  const char *kDummySigningIdentifier = "SigningID";
  process.signing_id.data = kDummySigningIdentifier;
  process.signing_id.length = std::strlen(kDummySigningIdentifier);

  const char *kDummyTeamIdentifier = "TeamID";
  process.team_id.data = kDummyTeamIdentifier;
  process.team_id.length = std::strlen(kDummyTeamIdentifier);

  const char *kDummyPath = "/path/to/application";
  es_file_t executable = {};
  executable.path.data = kDummyPath;
  executable.path.length = std::strlen(kDummyPath);

  process.executable = &executable;

  es_message_t es_message = {};
  es_message.event_type = ES_EVENT_TYPE_NOTIFY_OPEN;
  es_message.process = &process;

  const char *kDummyFilePath = "/path/to/file";
  es_file_t file = {};
  file.path.data = kDummyFilePath;
  file.path.length = std::strlen(kDummyFilePath);

  es_message.event.open.file = &file;

  IEndpointSecurityConsumer::Event::Header header;
  auto status =
      EndpointSecurityConsumer::initializeEventHeader(header, es_message);

  REQUIRE(status.succeeded());

  CHECK(header.timestamp != 0U);
  CHECK(header.parent_process_id == 10U);
  CHECK(header.orig_parent_process_id == 11U);
  CHECK(header.process_id == 245U);
  CHECK(header.user_id == 241U);
  CHECK(header.group_id == 242U);
  CHECK(header.platform_binary == 1U);
  CHECK(header.signing_id == kDummySigningIdentifier);
  CHECK(header.team_id == kDummyTeamIdentifier);
  CHECK(header.path == kDummyPath);
  CHECK(header.cdhash == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
  CHECK(header.file_path == kDummyFilePath);
}

TEST_CASE("Event header initialization for Create event with existing path",
          "[ZeekEndpointConsumer]") {
  es_process_t process = {};
  process.ppid = 10U;
  process.original_ppid = 11U;

  for (auto i = 0U; i < 8U; ++i) {
    process.audit_token.val[i] = 0xF0U + i;
  }

  process.is_platform_binary = 1U;

  for (auto i = 0U; i < sizeof(process.cdhash); ++i) {
    process.cdhash[i] = 0xA0U + i;
  }

  const char *kDummySigningIdentifier = "SigningID";
  process.signing_id.data = kDummySigningIdentifier;
  process.signing_id.length = std::strlen(kDummySigningIdentifier);

  const char *kDummyTeamIdentifier = "TeamID";
  process.team_id.data = kDummyTeamIdentifier;
  process.team_id.length = std::strlen(kDummyTeamIdentifier);

  const char *kDummyPath = "/path/to/application";
  es_file_t executable = {};
  executable.path.data = kDummyPath;
  executable.path.length = std::strlen(kDummyPath);

  process.executable = &executable;

  es_message_t es_message = {};
  es_message.event_type = ES_EVENT_TYPE_NOTIFY_CREATE;
  es_message.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
  es_message.process = &process;

  const char *kDummyFilePath = "/path/to/file";

  const char *kDummyDir = "/path/to";
  es_file_t newPathDir = {};
  newPathDir.path.data = kDummyDir;
  newPathDir.path.length = std::strlen(kDummyDir);

  es_message.event.create.destination.new_path.dir = &newPathDir;

  const char *kDummyFilename = "file";
  es_message.event.create.destination.new_path.filename.data = kDummyFilename;
  es_message.event.create.destination.new_path.filename.length =
      std::strlen(kDummyFilename);

  IEndpointSecurityConsumer::Event::Header header;
  auto status =
      EndpointSecurityConsumer::initializeEventHeader(header, es_message);

  REQUIRE(status.succeeded());

  CHECK(header.timestamp != 0U);
  CHECK(header.parent_process_id == 10U);
  CHECK(header.orig_parent_process_id == 11U);
  CHECK(header.process_id == 245U);
  CHECK(header.user_id == 241U);
  CHECK(header.group_id == 242U);
  CHECK(header.platform_binary == 1U);
  CHECK(header.signing_id == kDummySigningIdentifier);
  CHECK(header.team_id == kDummyTeamIdentifier);
  CHECK(header.path == kDummyPath);
  CHECK(header.cdhash == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
  CHECK(header.file_path == kDummyFilePath);
}

TEST_CASE("Event header initialization for Create event with new path",
          "[ZeekEndpointConsumer]") {
  es_process_t process = {};
  process.ppid = 10U;
  process.original_ppid = 11U;

  for (auto i = 0U; i < 8U; ++i) {
    process.audit_token.val[i] = 0xF0U + i;
  }

  process.is_platform_binary = 1U;

  for (auto i = 0U; i < sizeof(process.cdhash); ++i) {
    process.cdhash[i] = 0xA0U + i;
  }

  const char *kDummySigningIdentifier = "SigningID";
  process.signing_id.data = kDummySigningIdentifier;
  process.signing_id.length = std::strlen(kDummySigningIdentifier);

  const char *kDummyTeamIdentifier = "TeamID";
  process.team_id.data = kDummyTeamIdentifier;
  process.team_id.length = std::strlen(kDummyTeamIdentifier);

  const char *kDummyPath = "/path/to/application";
  es_file_t executable = {};
  executable.path.data = kDummyPath;
  executable.path.length = std::strlen(kDummyPath);

  process.executable = &executable;

  es_message_t es_message = {};
  es_message.event_type = ES_EVENT_TYPE_NOTIFY_CREATE;
  es_message.event.create.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
  es_message.process = &process;

  const char *kDummyFilePath = "/path/to/file";
  es_file_t existing_file = {};
  existing_file.path.data = kDummyFilePath;
  existing_file.path.length = std::strlen(kDummyFilePath);

  es_message.event.create.destination.existing_file = &existing_file;

  IEndpointSecurityConsumer::Event::Header header;
  auto status =
      EndpointSecurityConsumer::initializeEventHeader(header, es_message);

  REQUIRE(status.succeeded());

  CHECK(header.timestamp != 0U);
  CHECK(header.parent_process_id == 10U);
  CHECK(header.orig_parent_process_id == 11U);
  CHECK(header.process_id == 245U);
  CHECK(header.user_id == 241U);
  CHECK(header.group_id == 242U);
  CHECK(header.platform_binary == 1U);
  CHECK(header.signing_id == kDummySigningIdentifier);
  CHECK(header.team_id == kDummyTeamIdentifier);
  CHECK(header.path == kDummyPath);
  CHECK(header.cdhash == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
  CHECK(header.file_path == kDummyFilePath);
}
} // namespace zeek
