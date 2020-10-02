#include "fileeventstableplugin.h"
#include "utils.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Row generation in the file_events table", "[FileEventsTablePlugin]") {

  GIVEN("a valid create syscall audit event") {

    // clang-format off
    static const IAudispConsumer::AuditEvent kCreateAuditEvent = {
        // Syscall record data
        {
            IAudispConsumer::SyscallRecordData::Type::Create,
            0,
            38031,
            38030,
            true,
            1000,
            1000,
            1000,
            1000,
            1000,
            "/home/wajih/a.out",
            "560a3d760004"
        },

        // Execve record data
        {
        },

        // Path record data
        {
            {
                {
                    "/home/wajih",
                    040755,
                    1000,
                    1000,
                    668350
                },

                {
                    "file.txt",
                    0100744,
                    1000,
                    1000,
                    677951
                }
            }
        },

        // Cwd data
        {
            "/home/wajih"
        },

        // Sockaddr data
        {}
    };
    // clang-format on

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, kCreateAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedColumnList = {
            {"syscall", "create"},
            {"pid", kCreateAuditEvent.syscall_data.process_id},
            {"ppid", kCreateAuditEvent.syscall_data.parent_process_id},
            {"uid", kCreateAuditEvent.syscall_data.uid},
            {"gid", kCreateAuditEvent.syscall_data.gid},
            {"auid", kCreateAuditEvent.syscall_data.auid},
            {"euid", kCreateAuditEvent.syscall_data.euid},
            {"egid", kCreateAuditEvent.syscall_data.egid},
            {"exe", "/home/wajih/a.out"},
            {"path", "/home/wajih/file.txt"},
            {"inode", static_cast<std::int64_t>(677951)}};

        REQUIRE(row.size() == kExpectedColumnList.size() + 1);

        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedColumnList);
      }
    }
  }
  GIVEN("a valid open syscall audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kCreateAuditEvent = {
        // Syscall record data
        {
            IAudispConsumer::SyscallRecordData::Type::Open,
            0,
            38031,
            38030,
            true,
            500,
            500,
            500,
            500,
            500,
            "/bin/cat",
            "7fffd19c5592"
        },

        // Execve record data
        {
        },

        // Path record data
        {
            {
                {
                    "/etc/ssh/sshd_config",
                    0100600,
                    0,
                    0,
                    409242
                }
            }
        },

        // Cwd data
        {
            "/home/wajih"
        },

        // Sockaddr data
        {}
    };
    // clang-format on
    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, kCreateAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedColumnList = {
            {"syscall", "open"},
            {"pid", kCreateAuditEvent.syscall_data.process_id},
            {"ppid", kCreateAuditEvent.syscall_data.parent_process_id},
            {"uid", kCreateAuditEvent.syscall_data.uid},
            {"gid", kCreateAuditEvent.syscall_data.gid},
            {"auid", kCreateAuditEvent.syscall_data.auid},
            {"euid", kCreateAuditEvent.syscall_data.euid},
            {"egid", kCreateAuditEvent.syscall_data.egid},
            {"exe", "/bin/cat"},
            {"path", "/etc/ssh/sshd_config"},
            {"inode", static_cast<std::int64_t>(409242)}};

        REQUIRE(row.size() == kExpectedColumnList.size() + 1);

        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedColumnList);
      }
    }
  }

  GIVEN("a valid open syscall audit event with a space in AUDIT_PATH name field") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kCreateAuditEvent = {
        // Syscall record data
        {
            IAudispConsumer::SyscallRecordData::Type::Open,
            0,
            38031,
            38030,
            true,
            500,
            500,
            500,
            500,
            500,
            "/bin/cat",
            "7fffd19c5592"
        },

        // Execve record data
        {
        },

        // Path record data
        {
            {
                {
                    "\"/etc/nginx/nginx config\"",
                    0100600,
                    0,
                    0,
                    409242
                }
            }
        },

        // Cwd data
        {
            "/home/wajih"
        },

        // Sockaddr data
        {}
    };
    // clang-format on
    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, kCreateAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedColumnList = {
            {"syscall", "open"},
            {"pid", kCreateAuditEvent.syscall_data.process_id},
            {"ppid", kCreateAuditEvent.syscall_data.parent_process_id},
            {"uid", kCreateAuditEvent.syscall_data.uid},
            {"gid", kCreateAuditEvent.syscall_data.gid},
            {"auid", kCreateAuditEvent.syscall_data.auid},
            {"euid", kCreateAuditEvent.syscall_data.euid},
            {"egid", kCreateAuditEvent.syscall_data.egid},
            {"exe", "/bin/cat"},
            {"path", "/etc/nginx/nginx config"},
            {"inode", static_cast<std::int64_t>(409242)}};

        REQUIRE(row.size() == kExpectedColumnList.size() + 1);

        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedColumnList);
      }
    }
  }

  GIVEN("a valid openat syscall audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kCreateAuditEvent = {
        // Syscall record data
        {
            IAudispConsumer::SyscallRecordData::Type::OpenAt,
            0,
            38031,
            38030,
            true,
            1000,
            1000,
            1000,
            1000,
            1000,
            "/home/wajih/a.out",
            "ffffff9c"
        },

        // Execve record data
        {
        },

        // Path record data
        {
            {
                {
                    "/home/wajih",
                    040755,
                    1000,
                    1000,
                    786436
                },
                {
                    "file.txt",
                    0102430,
                    1000,
                    1000,
                    806807
                }
            }
        },

        // Cwd data
        {
            "/home/wajih"
        },

        // Sockaddr data
        {}
    };
    // clang-format on
    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status = FileEventsTablePlugin::generateRow(row, kCreateAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        static ExpectedValueList kExpectedColumnList = {
            {"syscall", "openat"},
            {"pid", kCreateAuditEvent.syscall_data.process_id},
            {"ppid", kCreateAuditEvent.syscall_data.parent_process_id},
            {"uid", kCreateAuditEvent.syscall_data.uid},
            {"gid", kCreateAuditEvent.syscall_data.gid},
            {"auid", kCreateAuditEvent.syscall_data.auid},
            {"euid", kCreateAuditEvent.syscall_data.euid},
            {"egid", kCreateAuditEvent.syscall_data.egid},
            {"exe", "/home/wajih/a.out"},
            {"path", "/home/wajih/file.txt"},
            {"inode", static_cast<std::int64_t>(806807)}};

        REQUIRE(row.size() == kExpectedColumnList.size() + 1);

        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedColumnList);
      }
    }
  }
}
} // namespace zeek
