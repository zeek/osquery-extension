#include "zeekconfiguration.h"

#include <catch2/catch.hpp>

namespace zeek {
TEST_CASE("Reading configuration files", "[ZeekConfiguration]") {
#ifdef WIN32
  const std::string kExpectedLogFolder{"C:\\logs\\zeek-agent"};
  const std::string kExpectedCertFile{"nul"};
  const std::string kExceptedOsqueryExtensionsSocket{"C:\\osquery_extensions_socket"};

  const std::string kTestConfiguration = R""(
  {
    "server_address": "127.0.0.1",
    "server_port": 9999,

    "log_folder": "C:\\logs\\zeek-agent",

    "group_list": [
      "test/group/0",
      "test/group/1"
    ],

    "authentication": {
      "certificate_authority": "nul",
      "client_certificate": "nul",
      "client_key": "nul"
    },

    "osquery_extensions_socket": "C:\\osquery_extensions_socket",
    "max_queued_row_count": 1337
  }
  )"";

#else
  const std::string kExpectedLogFolder{"/var/log/zeek"};
  const std::string kExpectedCertFile{"/dev/null"};
  const std::string kExceptedOsqueryExtensionsSocket{"/test/path"};

  const std::string kTestConfiguration = R""(
  {
    "server_address": "127.0.0.1",
    "server_port": 9999,

    "log_folder": "/var/log/zeek",

    "group_list": [
      "test/group/0",
      "test/group/1"
    ],

    "authentication": {
      "certificate_authority": "/dev/null",
      "client_certificate": "/dev/null",
      "client_key": "/dev/null"
    },

    "osquery_extensions_socket": "/test/path",
    "max_queued_row_count": 1337
  }
  )"";
#endif

  ZeekConfiguration::Context context;
  auto status =
      ZeekConfiguration::parseConfigurationData(context, kTestConfiguration);

  CHECK(status.message() == "");
  REQUIRE(status.succeeded());

  REQUIRE(context.server_address == "127.0.0.1");
  REQUIRE(context.server_port == 9999U);

  REQUIRE(context.log_folder == kExpectedLogFolder);

  REQUIRE(context.group_list.size() == 2U);
  REQUIRE(context.group_list.at(0U) == "test/group/0");
  REQUIRE(context.group_list.at(1U) == "test/group/1");

  REQUIRE(context.certificate_authority == kExpectedCertFile);
  REQUIRE(context.client_certificate == kExpectedCertFile);
  REQUIRE(context.client_key == kExpectedCertFile);
  REQUIRE(context.osquery_extensions_socket == kExceptedOsqueryExtensionsSocket);

  REQUIRE(context.max_queued_row_count == 1337U);
}
} // namespace zeek
