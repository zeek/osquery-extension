#include "audispconsumer.h"
#include "mockedaudispproducer.h"

#include <chrono>
#include <thread>

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("AudispConsumer event parsers", "[AudispConsumer]") {
  GIVEN("a full execve event") {
    // clang-format off
    static const std::string kExecveEvent = "type=SYSCALL msg=audit(1572891138.674:28907): arch=c000003e syscall=59 success=yes exit=0 a0=7ffddc903cc0 a1=7f4e2c51a940 a2=55989bc751c0 a3=8 items=2 ppid=11413 pid=11414 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm=\"cat\" exe=\"/bin/cat\" key=(null)\ntype=EXECVE msg=audit(1572891138.674:28907): argc=2 a0=\"cat\" a1=\"--version\"\ntype=CWD msg=audit(1572891138.674:28907): cwd=\"/var/log/audit\"\ntype=PATH msg=audit(1572891138.674:28907): item=0 name=\"/bin/cat\" inode=5689 dev=00:18 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\ntype=PATH msg=audit(1572891138.674:28907): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=6763 dev=00:18 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\ntype=PROCTITLE msg=audit(1572891138.674:28907): proctitle=636174002D2D76657273696F6E\n";
    // clang-format on

    IAudispConsumer::Ref audisp_consumer;

    {
      IAudispProducer::Ref audisp_producer;
      auto status = MockedAudispProducer::create(audisp_producer, kExecveEvent);
      REQUIRE(status.succeeded());

      status = AudispConsumer::createWithProducer(audisp_consumer,
                                                  std::move(audisp_producer));
      audisp_producer = {};

      REQUIRE(status.succeeded());
    }

    WHEN("processing the event") {
      // The classes are using libauparse under the hood, and unless we call
      // auparse_flush_feed, we can't be sure when everything gets processed
      for (std::size_t i = 0U; i < 2U; ++i) {
        auto status = audisp_consumer->processEvents();
        REQUIRE(status.succeeded());

        std::this_thread::sleep_for(std::chrono::seconds(1U));
      }

      THEN("all records have been included") {
        AudispConsumer::AuditEventList event_list;
        auto status = audisp_consumer->getEvents(event_list);
        REQUIRE(status.succeeded());

        REQUIRE(event_list.size() >= 1U);

        // Make sure all records that must be present in an execve system call
        // have been included. Check a value from each record
        const auto &first_event = event_list.at(0);
        REQUIRE(first_event.execve_data.has_value());
        REQUIRE(first_event.path_data.has_value());
        REQUIRE(first_event.cwd_data.has_value());
        REQUIRE(first_event.execve_data.has_value());
        REQUIRE(!first_event.sockaddr_data.has_value());

        const auto &syscall_record = first_event.syscall_data;
        const auto &execve_record = first_event.execve_data.value();
        const auto &path_record = first_event.path_data.value();
        const auto &cwd_data = first_event.cwd_data.value();

        REQUIRE(syscall_record.process_id == 11414);
        REQUIRE(execve_record.argc == 2);

        REQUIRE(path_record.size() == 2U);
        REQUIRE(path_record.at(0).mode == 0100755);

        REQUIRE(cwd_data == "/var/log/audit");
      }
    }
  }

  GIVEN("a bind() event") {
    // clang-format off
    static const std::string kBindEvent = "type=SYSCALL msg=audit(1573593461.740:303): arch=c000003e syscall=49 success=yes exit=0 a0=3 a1=56287aa33290 a2=10 a3=7ffdbe219c8c items=0 ppid=14019 pid=14223 auid=4294967295 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts2 ses=4294967295 comm=\"nc\" exe=\"/bin/nc.openbsd\" key=(null)\ntype=SOCKADDR msg=audit(1573593461.740:303): saddr=0200270F000000000000000000000000\ntype=PROCTITLE msg=audit(1573593461.740:303): proctitle=6E63002D6C00302E302E302E30002D700039393939\n";
    // clang-format on

    IAudispConsumer::Ref audisp_consumer;

    {
      IAudispProducer::Ref audisp_producer;
      auto status = MockedAudispProducer::create(audisp_producer, kBindEvent);
      REQUIRE(status.succeeded());

      status = AudispConsumer::createWithProducer(audisp_consumer,
                                                  std::move(audisp_producer));
      audisp_producer = {};

      REQUIRE(status.succeeded());
    }

    WHEN("processing the event") {
      // The classes are using libauparse under the hood, and unless we call
      // auparse_flush_feed, we can't be sure when everything gets processed
      for (std::size_t i = 0U; i < 2U; ++i) {
        auto status = audisp_consumer->processEvents();
        REQUIRE(status.succeeded());

        std::this_thread::sleep_for(std::chrono::seconds(1U));
      }

      THEN("all records have been included") {
        AudispConsumer::AuditEventList event_list;
        auto status = audisp_consumer->getEvents(event_list);
        REQUIRE(status.succeeded());

        REQUIRE(event_list.size() >= 1U);

        // Make sure all records that must be present in a bind() system call
        // have been included. Check a value from each record
        const auto &first_event = event_list.at(0);
        REQUIRE(!first_event.execve_data.has_value());
        REQUIRE(!first_event.path_data.has_value());
        REQUIRE(!first_event.cwd_data.has_value());
        REQUIRE(!first_event.execve_data.has_value());
        REQUIRE(first_event.sockaddr_data.has_value());

        const auto &syscall_record = first_event.syscall_data;
        const auto &sockaddr_record = first_event.sockaddr_data.value();

        REQUIRE(syscall_record.process_id == 14223);
        REQUIRE(sockaddr_record.port == 9999);
      }
    }
  }
}
} // namespace zeek
