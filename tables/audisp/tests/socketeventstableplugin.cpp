#include "socketeventstableplugin.h"
#include "utils.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Row generation in the socket_events table",
         "[SocketEventsTablePlugin]") {

  GIVEN("a valid connect audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kConnectAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Connect,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "/usr/bin/curl",
        "10"
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {
        {
          2,
          443,
          "127.0.0.1"
        }
      }
    };
    // clang-format on

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status =
          SocketEventsTablePlugin::generateRow(row, kConnectAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedConnectColumnList = {
            {"syscall", "connect"},
            {"pid", kConnectAuditEvent.syscall_data.process_id},
            {"ppid", kConnectAuditEvent.syscall_data.parent_process_id},
            {"auid", kConnectAuditEvent.syscall_data.auid},
            {"uid", kConnectAuditEvent.syscall_data.uid},
            {"euid", kConnectAuditEvent.syscall_data.euid},
            {"gid", kConnectAuditEvent.syscall_data.gid},
            {"egid", kConnectAuditEvent.syscall_data.egid},
            {"exe", "/usr/bin/curl"},
            {"fd", static_cast<std::int64_t>(16)},
            {"success", static_cast<std::int64_t>(1)},
            {"family", static_cast<std::int64_t>(2)},
            {"local_address", {""}},
            {"remote_address", "127.0.0.1"},
            {"local_port", {static_cast<std::int64_t>(0)}},
            {"remote_port", static_cast<std::int64_t>(443)}};

        REQUIRE(row.size() == kExpectedConnectColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedConnectColumnList);
      }
    }
  }

  GIVEN("a valid bind audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kBindAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Bind,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "/usr/bin/curl",
        "10"
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {
        {
          2,
          8080,
          "0.0.0.0"
        }
      }
    };
    // clang-format on

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = SocketEventsTablePlugin::generateRow(row, kBindAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedBindColumnList = {
            {"syscall", "bind"},
            {"pid", kBindAuditEvent.syscall_data.process_id},
            {"ppid", kBindAuditEvent.syscall_data.parent_process_id},
            {"auid", kBindAuditEvent.syscall_data.auid},
            {"uid", kBindAuditEvent.syscall_data.uid},
            {"euid", kBindAuditEvent.syscall_data.euid},
            {"gid", kBindAuditEvent.syscall_data.gid},
            {"egid", kBindAuditEvent.syscall_data.egid},
            {"exe", "/usr/bin/curl"},
            {"fd", static_cast<std::int64_t>(16)},
            {"success", static_cast<std::int64_t>(1)},
            {"family", static_cast<std::int64_t>(2)},
            {"local_address", "0.0.0.0"},
            {"remote_address", {""}},
            {"local_port", static_cast<std::int64_t>(8080)},
            {"remote_port", {static_cast<std::int64_t>(0)}}};

        REQUIRE(row.size() == kExpectedBindColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedBindColumnList);
      }
    }
  }
}
} // namespace zeek
