#include "processeventstableplugin.h"
#include "utils.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Row generation in the process_events table",
         "[ProcessEventsTablePlugin]") {

  GIVEN("a valid execve audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kExecveAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Execve,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "23eb8e0",
        "\"/usr/bin/bash\""
      },

      // Execve record data
      {
        {
          2,
          {
            "-c",
            "echo hello world!"
          }
        }
      },

      // Path record data
      {
        {
          {
            "/usr/bin/bash",
            0755,
            0,
            0
          },

          {
            "/lib64/ld-linux-x86-64.so.2",
            0755,
            0,
            0
          }
        }
      },

      // Cwd data
      {
        "/root"
      },

      // Sockaddr data
      {}
    };
    // clang-format on

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status =
          ProcessEventsTablePlugin::generateRow(row, kExecveAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedColumnList = {
          { "syscall", "execve" },
          { "pid", kExecveAuditEvent.syscall_data.process_id },
          { "parent", kExecveAuditEvent.syscall_data.parent_process_id },
          { "auid", kExecveAuditEvent.syscall_data.auid },
          { "uid", kExecveAuditEvent.syscall_data.uid },
          { "euid", kExecveAuditEvent.syscall_data.euid },
          { "gid", kExecveAuditEvent.syscall_data.gid },
          { "egid", kExecveAuditEvent.syscall_data.egid },
          { "owner_uid", static_cast<std::int64_t>(0) },
          { "owner_gid", static_cast<std::int64_t>(0) },
          { "cmdline_size", static_cast<std::int64_t>(24) },
          { "cmdline", "\"-c\" \"echo hello world!\"" },
          { "path", "/usr/bin/bash" },
          { "mode", static_cast<std::int64_t>(0755) },
          { "cwd", "/root" }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedColumnList.size() + 1);

        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedColumnList);
      }
    }
  }

  GIVEN("a valid fork audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kForkAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Fork,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "23eb8e0",
        "\"/usr/bin/bash\""
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {}
    };
    // clang-format on

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = ProcessEventsTablePlugin::generateRow(row, kForkAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedForkColumnList = {
          { "syscall", "fork" },
          { "pid", kForkAuditEvent.syscall_data.process_id },
          { "parent", kForkAuditEvent.syscall_data.parent_process_id },
          { "auid", kForkAuditEvent.syscall_data.auid },
          { "uid", kForkAuditEvent.syscall_data.uid },
          { "euid", kForkAuditEvent.syscall_data.euid },
          { "gid", kForkAuditEvent.syscall_data.gid },
          { "egid", kForkAuditEvent.syscall_data.egid },
          { "owner_uid", { static_cast<std::int64_t>(0) } },
          { "owner_gid", { static_cast<std::int64_t>(0) } },
          { "cmdline_size", { static_cast<std::int64_t>(0) } },
          { "cmdline", { "" } },
          { "path", { "" } },
          { "mode", { static_cast<std::int64_t>(0) } },
          { "cwd", { "" } }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedForkColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedForkColumnList);
      }
    }
  }

  GIVEN("a valid vfork audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kVForkAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::VFork,
        1,
        48031,
        48030,
        true,
        2000,
        2000,
        2000,
        2000,
        2000,
        "23eb8e0",
        "\"/usr/bin/bash\""
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {}
    };
    // clang-format on

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status =
          ProcessEventsTablePlugin::generateRow(row, kVForkAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedVForkColumnList = {
          { "syscall", "vfork" },
          { "pid", kVForkAuditEvent.syscall_data.process_id },
          { "parent", kVForkAuditEvent.syscall_data.parent_process_id },
          { "auid", kVForkAuditEvent.syscall_data.auid },
          { "uid", kVForkAuditEvent.syscall_data.uid },
          { "euid", kVForkAuditEvent.syscall_data.euid },
          { "gid", kVForkAuditEvent.syscall_data.gid },
          { "egid", kVForkAuditEvent.syscall_data.egid },
          { "owner_uid", { static_cast<std::int64_t>(0) } },
          { "owner_gid", { static_cast<std::int64_t>(0) } },
          { "cmdline_size", { static_cast<std::int64_t>(0) } },
          { "cmdline", { "" } },
          { "path", { "" } },
          { "mode", { static_cast<std::int64_t>(0) } },
          { "cwd", { "" } }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedVForkColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedVForkColumnList);
      }
    }
  }

  GIVEN("a valid clone audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kCloneAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Clone,
        2,
        58031,
        58030,
        true,
        3000,
        3000,
        3000,
        3000,
        3000,
        "23eb8e0",
        "\"/usr/bin/bash\""
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {}
    };
    // clang-format on

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status =
          ProcessEventsTablePlugin::generateRow(row, kCloneAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedCloneColumnList = {
          { "syscall", "clone" },
          { "pid", kCloneAuditEvent.syscall_data.process_id },
          { "parent", kCloneAuditEvent.syscall_data.parent_process_id },
          { "auid", kCloneAuditEvent.syscall_data.auid },
          { "uid", kCloneAuditEvent.syscall_data.uid },
          { "euid", kCloneAuditEvent.syscall_data.euid },
          { "gid", kCloneAuditEvent.syscall_data.gid },
          { "egid", kCloneAuditEvent.syscall_data.egid },
          { "owner_uid", { static_cast<std::int64_t>(0) } },
          { "owner_gid", { static_cast<std::int64_t>(0) } },
          { "cmdline_size", { static_cast<std::int64_t>(0) } },
          { "cmdline", { "" } },
          { "path", { "" } },
          { "mode", { static_cast<std::int64_t>(0) } },
          { "cwd", { "" } }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedCloneColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedCloneColumnList);
      }
    }
  }
}
} // namespace zeek
