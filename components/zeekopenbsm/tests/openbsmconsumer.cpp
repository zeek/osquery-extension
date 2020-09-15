#include "openbsmconsumer.h"

#include <arpa/inet.h>
#include <bsm/audit_kevents.h>
#include <bsm/libbsm.h>
#include <catch2/catch.hpp>
#include <string>

namespace zeek {
TEST_CASE(
    "Populating IOpenbsmconsumer::Event given OpenBSM token for Connect event",
    "[ZeekOpenbsmConsumer]") {
  std::vector<tokenstr_t> tokens = {};
  tokenstr_t tok_header, tok_subject, tok_socketinet, tok_return;

  tok_header.id = AUT_HEADER32;
  tok_header.tt.hdr32.s = 0U;
  tok_header.tt.hdr32.e_type = AUE_CONNECT;

  tok_socketinet.id = AUT_SOCKINET32;
  tok_socketinet.tt.sockinet_ex32.port = 443;
  tok_socketinet.tt.sockinet_ex32.family = 2;
  struct in_addr inaddr {};
  inet_pton(AF_INET, "1.2.3.4", &inaddr);
  memcpy(tok_socketinet.tt.sockinet_ex32.addr, &inaddr, sizeof(inaddr));

  tok_subject.id = AUT_SUBJECT32;
  tok_subject.tt.subj32.pid = 1U;
  tok_subject.tt.subj32.euid = 2U;
  tok_subject.tt.subj32.egid = 3U;

  tok_return.id = AUT_RETURN32;

  tokens.push_back(tok_header);
  tokens.push_back(tok_socketinet);
  tokens.push_back(tok_subject);
  tokens.push_back(tok_return);

  IOpenbsmConsumer::Event event;
  auto status = OpenbsmConsumer::populateEventFromTokens(event, tokens);

  REQUIRE(status.succeeded());

  REQUIRE(event.type == IOpenbsmConsumer::Event::Type::Connect);
  REQUIRE(event.header.timestamp == 0U);
  REQUIRE(event.header.process_id == 1U);
  REQUIRE(event.header.path == "/sbin/launchd");
  REQUIRE(event.header.user_id == 2U);
  REQUIRE(event.header.group_id == 3U);
  REQUIRE(event.header.local_port == 0);
  REQUIRE(event.header.local_address == "");
  REQUIRE(event.header.remote_port == htons(443));
  REQUIRE(event.header.remote_address == "1.2.3.4");
  REQUIRE(event.header.family == 2);
}

TEST_CASE("Populating IOpenbsmconsumer::Event given OpenBSM token for Connect "
          "event with IPv6",
          "[ZeekOpenbsmConsumer]") {
  std::vector<tokenstr_t> tokens = {};
  tokenstr_t tok_header, tok_subject, tok_socketinet, tok_return;

  tok_header.id = AUT_HEADER32;
  tok_header.tt.hdr32.s = 0U;
  tok_header.tt.hdr32.e_type = AUE_CONNECT;

  tok_socketinet.id = AUT_SOCKINET32;
  tok_socketinet.tt.sockinet_ex32.port = 443;
  tok_socketinet.tt.sockinet_ex32.family = 26;
  struct in6_addr inaddr {};
  inet_pton(AF_INET6, "dead:beef:7654:3210:fedc:3210:7654:ba98", &inaddr);
  memcpy(tok_socketinet.tt.sockinet_ex32.addr, &inaddr, sizeof(inaddr));

  tok_subject.id = AUT_SUBJECT32;
  tok_subject.tt.subj32.pid = 1U;
  tok_subject.tt.subj32.euid = 2U;
  tok_subject.tt.subj32.egid = 3U;

  tok_return.id = AUT_RETURN32;

  tokens.push_back(tok_header);
  tokens.push_back(tok_socketinet);
  tokens.push_back(tok_subject);
  tokens.push_back(tok_return);

  IOpenbsmConsumer::Event event;
  auto status = OpenbsmConsumer::populateEventFromTokens(event, tokens);

  REQUIRE(status.succeeded());

  REQUIRE(event.type == IOpenbsmConsumer::Event::Type::Connect);
  REQUIRE(event.header.timestamp == 0U);
  REQUIRE(event.header.process_id == 1U);
  REQUIRE(event.header.path == "/sbin/launchd");
  REQUIRE(event.header.user_id == 2U);
  REQUIRE(event.header.group_id == 3U);
  REQUIRE(event.header.local_port == 0);
  REQUIRE(event.header.local_address == "");
  REQUIRE(event.header.remote_port == htons(443));
  REQUIRE(event.header.remote_address ==
          "dead:beef:7654:3210:fedc:3210:7654:ba98");
  REQUIRE(event.header.family == 10);
}

TEST_CASE(
    "Populating IOpenbsmconsumer::Event given OpenBSM token for Bind event",
    "[ZeekOpenbsmConsumer]") {
  std::vector<tokenstr_t> tokens = {};
  tokenstr_t tok_header, tok_subject, tok_socketinet, tok_return;

  tok_header.id = AUT_HEADER32;
  tok_header.tt.hdr32.s = 0U;
  tok_header.tt.hdr32.e_type = AUE_BIND;

  tok_socketinet.id = AUT_SOCKINET32;
  tok_socketinet.tt.sockinet_ex32.port = 443;
  tok_socketinet.tt.sockinet_ex32.family = 2;
  struct in_addr inaddr {};
  inet_pton(AF_INET, "1.2.3.4", &inaddr);
  memcpy(tok_socketinet.tt.sockinet_ex32.addr, &inaddr, sizeof(inaddr));

  tok_subject.id = AUT_SUBJECT32;
  tok_subject.tt.subj32.pid = 1U;
  tok_subject.tt.subj32.euid = 2U;
  tok_subject.tt.subj32.egid = 3U;

  tok_return.id = AUT_RETURN32;

  tokens.push_back(tok_header);
  tokens.push_back(tok_socketinet);
  tokens.push_back(tok_subject);
  tokens.push_back(tok_return);

  IOpenbsmConsumer::Event event;
  auto status = OpenbsmConsumer::populateEventFromTokens(event, tokens);

  REQUIRE(status.succeeded());

  REQUIRE(event.type == IOpenbsmConsumer::Event::Type::Bind);
  REQUIRE(event.header.timestamp == 0U);
  REQUIRE(event.header.process_id == 1U);
  REQUIRE(event.header.path == "/sbin/launchd");
  REQUIRE(event.header.user_id == 2U);
  REQUIRE(event.header.group_id == 3U);
  REQUIRE(event.header.remote_port == 0);
  REQUIRE(event.header.remote_address == "");
  REQUIRE(event.header.local_port == htons(443));
  REQUIRE(event.header.local_address == "1.2.3.4");
  REQUIRE(event.header.family == 2);
}

TEST_CASE("Populating IOpenbsmconsumer::Event given OpenBSM token for Bind "
          "event with IPv6",
          "[ZeekOpenbsmConsumer]") {
  std::vector<tokenstr_t> tokens = {};
  tokenstr_t tok_header, tok_subject, tok_socketinet, tok_return;

  tok_header.id = AUT_HEADER32;
  tok_header.tt.hdr32.s = 0U;
  tok_header.tt.hdr32.e_type = AUE_BIND;

  tok_socketinet.id = AUT_SOCKINET32;
  tok_socketinet.tt.sockinet_ex32.port = 443;
  tok_socketinet.tt.sockinet_ex32.family = 26;
  struct in6_addr inaddr {};
  inet_pton(AF_INET6, "dead:beef:7654:3210:fedc:3210:7654:ba98", &inaddr);
  memcpy(tok_socketinet.tt.sockinet_ex32.addr, &inaddr, sizeof(inaddr));

  tok_subject.id = AUT_SUBJECT32;
  tok_subject.tt.subj32.pid = 1U;
  tok_subject.tt.subj32.euid = 2U;
  tok_subject.tt.subj32.egid = 3U;

  tok_return.id = AUT_RETURN32;

  tokens.push_back(tok_header);
  tokens.push_back(tok_socketinet);
  tokens.push_back(tok_subject);
  tokens.push_back(tok_return);

  IOpenbsmConsumer::Event event;
  auto status = OpenbsmConsumer::populateEventFromTokens(event, tokens);

  REQUIRE(status.succeeded());

  REQUIRE(event.type == IOpenbsmConsumer::Event::Type::Bind);
  REQUIRE(event.header.timestamp == 0U);
  REQUIRE(event.header.process_id == 1U);
  REQUIRE(event.header.path == "/sbin/launchd");
  REQUIRE(event.header.user_id == 2U);
  REQUIRE(event.header.group_id == 3U);
  REQUIRE(event.header.remote_port == 0);
  REQUIRE(event.header.remote_address == "");
  REQUIRE(event.header.local_port == htons(443));
  REQUIRE(event.header.local_address ==
          "dead:beef:7654:3210:fedc:3210:7654:ba98");
  REQUIRE(event.header.family == 10);
}
} // namespace zeek
