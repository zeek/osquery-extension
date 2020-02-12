#include "endpointsecurityconsumer.h"

#include <iostream>

#include <catch2/catch.hpp>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

namespace zeek {
TEST_CASE("Event header initialization", "[ZeekEndpointConsumer]") {
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
      EndpointSecurityConsumer::initializeEventHeader(header, &es_message);

  REQUIRE(status.succeeded());

  REQUIRE(header.timestamp != 0U);
  REQUIRE(header.parent_process_id == 10U);
  REQUIRE(header.orig_parent_process_id == 11U);
  REQUIRE(header.process_id == 245U);
  REQUIRE(header.user_id == 241U);
  REQUIRE(header.group_id == 242U);
  REQUIRE(header.platform_binary == 1U);
  REQUIRE(header.signing_id == kDummySigningIdentifier);
  REQUIRE(header.team_id == kDummyTeamIdentifier);
  REQUIRE(header.path == kDummyPath);
  REQUIRE(header.cdhash == "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3");
}
} // namespace zeek
