#include "zeekconnection.h"

#include <catch2/catch.hpp>

namespace zeek {
TEST_CASE("Query differentials", "[ZeekConnection]") {
  // clang-format off
  static const IVirtualDatabase::QueryOutput kQueryOutput01 = {
    // Row 1 (added)
    {
      { "Key", "test_key_name1" },
      { "Value", "value1" }
    },

    // Row 2 (added)
    {
      { "Key", "test_key_name2" },
      { "Value", "value2" }
    },

    // Row 3 (added)
    {
      { "Key", "test_key_name3" },
      { "Value", "value3" }
    }
  };
  // clang-format on

  // clang-format off
  static const IVirtualDatabase::QueryOutput kQueryOutput02 = {
    // Row 1 (ignored)
    {
      { "Key", "test_key_name1" },
      { "Value", "value1" }
    },

    // Row 2
    // (removed)

    // Row 3 (ignored)
    {
      { "Key", "test_key_name3" },
      { "Value", "value3" }
    }
  };
  // clang-format on

  // clang-format off
  static const IVirtualDatabase::QueryOutput kQueryOutput03 = {
    // Row 1
    // (removed)

    // Row 2 (added)
    {
      { "Key", "test_key_name2" },
      { "Value", "value2" }
    }

    // Row 3
    // (removed)
  };
  // clang-format on

  // First of all, make sure that the three types of rows we prepared all
  // have different hashes
  static const std::vector<
      std::reference_wrapper<const IVirtualDatabase::QueryOutput>>
      kQueryOutputList = {kQueryOutput01, kQueryOutput02, kQueryOutput03};

  std::set<std::uint64_t> row_hash_set;

  for (const auto &query_output_ref : kQueryOutputList) {
    const auto &query_output = query_output_ref.get();

    for (const auto &row : query_output) {
      std::uint64_t hash{0U};
      auto status = ZeekConnection::computeQueryOutputHash(hash, row);
      REQUIRE(status.succeeded());

      row_hash_set.insert(hash);
    }
  }

  REQUIRE(row_hash_set.size() == 3U);

  //
  // Attempt to compute differentials
  //

  ZeekConnection::DifferentialContext diff_context;

  QueryScheduler::TaskOutput task_output;
  task_output.response_topic = "DummyResponseTopic";
  task_output.response_event = "DummyResponseEvent";
  task_output.cookie = "DummyCookie";
  task_output.update_type = QueryScheduler::Task::UpdateType::Both;

  // On the first run, we expect to have 3 rows added and 0 removed. This should
  // be marked as initial state
  ZeekConnection::DifferentialOutput diff_output;
  bool initial_state{false};

  task_output.query_output = kQueryOutput01;
  auto status = ZeekConnection::computeDifferentials(
      diff_context, diff_output, initial_state, task_output);

  REQUIRE(status.succeeded());
  REQUIRE(initial_state);
  REQUIRE(diff_output.added_row_list.size() == 3U);
  REQUIRE(diff_output.removed_row_list.empty());

  // On the second run, the output has not changed. From now on, the
  // initial_state variable should always be set to false
  task_output.query_output = kQueryOutput01;
  status = ZeekConnection::computeDifferentials(diff_context, diff_output,
                                                initial_state, task_output);

  REQUIRE(status.succeeded());
  REQUIRE(!initial_state);
  REQUIRE(diff_output.added_row_list.empty());
  REQUIRE(diff_output.removed_row_list.empty());

  // On the third run, one row has been removed, while the other two
  // have been left intact
  task_output.query_output = kQueryOutput02;
  status = ZeekConnection::computeDifferentials(diff_context, diff_output,
                                                initial_state, task_output);

  REQUIRE(status.succeeded());
  REQUIRE(!initial_state);
  REQUIRE(diff_output.added_row_list.empty());
  REQUIRE(diff_output.removed_row_list.size() == 1U);

  // On the fourth run, two rows have disappeared and one has been restored
  task_output.query_output = kQueryOutput03;
  status = ZeekConnection::computeDifferentials(diff_context, diff_output,
                                                initial_state, task_output);

  REQUIRE(status.succeeded());
  REQUIRE(!initial_state);
  REQUIRE(diff_output.added_row_list.size() == 1U);
  REQUIRE(diff_output.removed_row_list.size() == 2U);
}
} // namespace zeek
