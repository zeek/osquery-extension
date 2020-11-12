#include "zeekconnection.h"
#include "configuration.h"
#include "logger.h"
#include "uniquexxh64state.h"
#include "utils.h"

#include <unordered_map>

#include <broker/endpoint.hh>
#include <broker/zeek.hh>

#include <zeek/network.h>
#include <zeek/system_identifiers.h>

namespace zeek {
namespace {
#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
const std::string kZeekAgentEdition{"osquery"};
#else
const std::string kZeekAgentEdition{"standalone"};
#endif

const std::string kHostSubscribeEvent{"ZeekAgent::host_subscribe"};
const std::string kHostUnsubscribeEvent{"ZeekAgent::host_unsubscribe"};
const std::string kHostJoinEvent{"ZeekAgent::host_join"};
const std::string kHostLeaveEvent{"ZeekAgent::host_leave"};
const std::string kHostExecuteEvent{"ZeekAgent::host_execute"};

const std::string kBrokerTopic_ALL{"/zeek/zeek-agent/hosts"};
const std::string kBrokerTopic_ANNOUNCE{"/zeek/zeek-agent/host_announce"};
const std::string kBrokerTopic_PRE_INDIVIDUALS{"/zeek/zeek-agent/host/"};
const std::string kBrokerTopic_PRE_GROUPS{"/zeek/zeek-agent/group/"};
const std::string kBrokerEvent_HOST_NEW{"ZeekAgent::host_new"};

template <typename FieldType, int field_index>
FieldType getZeekEventField(const broker::zeek::Event &event) {
  const auto &argument_list = event.args();
  if (field_index >= argument_list.size()) {
    throw Status::failure("Field does not exists");
  }

  const auto &argument = argument_list[field_index];
  if (!broker::is<FieldType>(argument)) {
    throw Status::failure("Field is of wrong type");
  }

  return broker::get<FieldType>(argument);
}

auto getZeekEventResponseEventName = getZeekEventField<std::string, 0>;
auto getZeekEventQueryString = getZeekEventField<std::string, 1>;
auto getZeekEventCookie = getZeekEventField<std::string, 2>;
auto getZeekEventResponseTopic = getZeekEventField<std::string, 3>;
auto getZeekEventUpdateType = getZeekEventField<std::string, 4>;
auto getZeekEventInterval = getZeekEventField<std::uint64_t, 5>;
} // namespace

struct ZeekConnection::PrivateData final {
  PrivateData(broker::configuration config)
      : broker_endpoint(new broker::endpoint(std::move(config))),
        status_subscriber(broker_endpoint->make_status_subscriber(true)) {}

  std::string peer_name;
  std::string host_identifier;
  std::unique_ptr<broker::endpoint> broker_endpoint;

  broker::status_subscriber status_subscriber;

  std::unordered_map<std::string, broker::subscriber> subscriber_map;
  std::vector<std::string> joined_group_list;

  QueryScheduler::TaskQueue task_queue;
  DifferentialContext differential_context;
};

Status ZeekConnection::create(Ref &obj, const std::string &host_identifier) {
  try {
    obj.reset();

    auto ptr = new ZeekConnection(host_identifier);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekConnection::~ZeekConnection() { d->broker_endpoint->shutdown(); }

Status ZeekConnection::joinGroup(const std::string &name) {
  auto group_it =
      std::find(d->joined_group_list.begin(), d->joined_group_list.end(), name);

  if (group_it != d->joined_group_list.end()) {
    return Status::failure("The following group has already been joined: " +
                           name);
  }

  auto status = createSubscription(kBrokerTopic_PRE_GROUPS + name);
  if (!status.succeeded()) {
    throw status;
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "A new group has been joined: " + name);

  d->joined_group_list.push_back(name);
  return Status::success();
}

Status ZeekConnection::leaveGroup(const std::string &name) {
  auto group_it =
      std::find(d->joined_group_list.begin(), d->joined_group_list.end(), name);

  if (group_it == d->joined_group_list.end()) {
    return Status::failure("The following group has not been joined: " + name);
  }

  auto status = destroySubscription(kBrokerTopic_PRE_GROUPS + name);
  if (!status.succeeded()) {
    return status;
  }

  d->joined_group_list.erase(group_it);
  return Status::success();
}

Status ZeekConnection::processEvents() {
  StatusEventList status_event_list;
  auto status = getStatusEvents(status_event_list);
  if (!status.succeeded()) {
    return status;
  }

  if (!status_event_list.empty()) {
    // Whatever happened, we are either disconnected or have just
    // reconnected (in which case we have to reset the connection state)
    return Status::failure("Connection hase been lost or reset");
  }

  bool ready{false};
  status = waitForActivity(ready);
  if (!status.succeeded()) {
    return status;
  }

  if (!ready) {
    return Status::success();
  }

  for (auto &subscriber_p : d->subscriber_map) {
    auto &subscriber = subscriber_p.second;

    for (const auto &message : subscriber.poll()) {
      broker::zeek::Event event(caf::get<1>(message));

      if (event.name() == kHostJoinEvent || event.name() == kHostLeaveEvent) {
        const auto &argument_list = event.args();

        if (argument_list.size() != 1U) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 "Invalid host_join/host_leave event received "
                                 "(wrong argument count)");

          continue;
        }

        auto group_name_ptr = broker::get_if<std::string>(argument_list[0]);
        if (group_name_ptr == nullptr) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 "Invalid host_join/host_leave event received "
                                 "(missing or invalid group name)");

          continue;
        }

        const auto &group_name = *group_name_ptr;

        if (event.name() == kHostJoinEvent) {
          status = joinGroup(group_name);
        } else {
          status = leaveGroup(group_name);
        }

        if (!status.succeeded()) {
          getLogger().logMessage(
              IZeekLogger::Severity::Error,
              "Failed to handle host_join/host_leave event: " +
                  status.message());
        }

      } else {
        QueryScheduler::Task pending_task;

        status = taskFromZeekEvent(pending_task, event);
        if (!status.succeeded()) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 status.message());

        } else {
          if (pending_task.type ==
              QueryScheduler::Task::Type::RemoveScheduledQuery) {
            auto query_id = computeQueryID(pending_task.response_topic,
                                           pending_task.response_event,
                                           pending_task.cookie);

            d->differential_context.erase(query_id);
          }

          d->task_queue.push_back(std::move(pending_task));
        }
      }
    }
  }

  return Status::success();
}

QueryScheduler::TaskQueue ZeekConnection::getTaskQueue() {
  auto output = std::move(d->task_queue);
  d->task_queue = {};

  return output;
}

void ZeekConnection::publishTaskOutput(
    const std::string &trigger, const std::string &response_topic,
    const std::string &response_event, const std::string &cookie,
    const IVirtualDatabase::QueryOutput &query_output) {

  // clang-format off
  broker::vector message_header(
    {
      broker::data(d->host_identifier),
      broker::data(broker::data(broker::enum_value{trigger})),
      broker::data(cookie)
    }
  );
  // clang-format on

  for (const auto &row : query_output) {
    broker::vector message_data = {broker::data(message_header)};

    bool skip_row = false;

    for (const auto &column : row) {
      broker::data column_value = {};

      if (column.data.has_value()) {
        const auto &column_variant = column.data.value();

        if (std::holds_alternative<std::string>(column_variant)) {
          const auto &string_value = std::get<std::string>(column_variant);
          column_value = broker::data(string_value);

        } else if (std::holds_alternative<std::int64_t>(column_variant)) {
          auto integer_value = std::get<std::int64_t>(column_variant);
          column_value = broker::data(integer_value);

        } else if (std::holds_alternative<double>(column_variant)) {
          auto double_value = std::get<double>(column_variant);
          column_value = broker::data(double_value);

        } else {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 "Invalid type received");
          skip_row = true;
          break;
        }

      } else {
        getLogger().logMessage(IZeekLogger::Severity::Warning,
                               "Returning a NULL column. This may not be "
                               "correctly supported by Zeek");

        column_value = broker::data();
      }

      message_data.push_back(std::move(column_value));
    }

    if (!skip_row) {
      // clang-format off
      d->broker_endpoint->publish(
        response_topic,
        broker::zeek::Event(response_event, message_data)
      );
      // clang-format on
    }
  }
}

Status ZeekConnection::processTaskOutput(
    const QueryScheduler::TaskOutput &task_output) {

  if (task_output.update_type.has_value()) {
    DifferentialOutput differential_output;
    auto status = computeDifferentials(d->differential_context,
                                       differential_output, task_output);
    if (!status.succeeded()) {
      return status;
    }

    publishTaskOutput("ZeekAgent::ADD", task_output.response_topic,
                      task_output.response_event, task_output.cookie,
                      differential_output.added_row_list);

    publishTaskOutput("ZeekAgent::REMOVE", task_output.response_topic,
                      task_output.response_event, task_output.cookie,
                      differential_output.removed_row_list);

  } else {
    publishTaskOutput("ZeekAgent::SNAPSHOT", task_output.response_topic,
                      task_output.response_event, task_output.cookie,
                      task_output.query_output);
  }

  return Status::success();
}

Status ZeekConnection::processTaskOutputList(
    QueryScheduler::TaskOutputList task_output_list) {

  for (const auto &task_output : task_output_list) {
    auto status = processTaskOutput(task_output);
    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

Status ZeekConnection::waitForActivity(bool &ready) {
  ready = false;

  fd_set fd_list;
  FD_ZERO(&fd_list);

  int highest_socket_fd = -1;

  for (const auto &subscriber_p : d->subscriber_map) {
    const auto &subscriber = subscriber_p.second;

    auto socket = subscriber.fd();
    FD_SET(socket, &fd_list);

    highest_socket_fd = std::max(highest_socket_fd, socket);
  }

  struct timeval timeout {};
  timeout.tv_sec = 1;

  auto select_err =
      select(highest_socket_fd + 1, &fd_list, nullptr, nullptr, &timeout);
  if (select_err == 0) {
    return Status::success();

  } else if (select_err == -1) {
#ifdef WIN32
    auto error_code = WSAGetLastError();
    auto eintr_value = WSAEINTR;
#else
    auto error_code = errno;
    auto eintr_value = EINTR;
#endif

    if (error_code == eintr_value) {
      return Status::success();
    }

    return Status::failure("poll() has failed with error " +
                           std::to_string(error_code));
  }

  ready = true;
  return Status::success();
}

ZeekConnection::ZeekConnection(const std::string &host_identifier)
    : d(new PrivateData(getBrokerConfiguration())) {

  d->peer_name = getSystemHostname();
  d->host_identifier = host_identifier;

  const auto &server_address = getConfig().serverAddress();
  auto server_port = getConfig().serverPort();

  d->broker_endpoint->peer_nosync(server_address, server_port,
                                  broker::timeout::seconds(3));

  bool connected{false};

  for (std::size_t retry = 0U; retry < 5U; ++retry) {
    std::this_thread::sleep_for(std::chrono::seconds(1U));

    StatusEventList status_event_list;
    auto status = getStatusEvents(status_event_list);
    if (!status.succeeded()) {
      throw status;
    }

    for (const auto &status_code : status_event_list) {
      switch (status_code) {
      case broker::sc::peer_added:
        connected = true;
        break;

      case broker::sc::peer_lost:
      case broker::sc::peer_removed:
        connected = false;
        break;

      case broker::sc::unspecified:
      default:
        break;
      }
    }

    if (connected) {
      break;
    }
  }

  if (!connected) {
    throw Status::failure("The connection to the Zeek server timed out");
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Successfully connected to " + server_address + ":" +
                             std::to_string(server_port));

  auto status = createSubscription(kBrokerTopic_ALL);
  if (!status.succeeded()) {
    throw status;
  }

  status =
      createSubscription(kBrokerTopic_PRE_INDIVIDUALS + d->host_identifier);

  if (!status.succeeded()) {
    throw status;
  }

  for (const auto &group_name : getConfig().groupList()) {
    status = joinGroup(group_name);
    if (!status.succeeded()) {
      throw status;
    }
  }

  broker::vector joined_group_list;

  for (const auto &group : d->joined_group_list) {
    joined_group_list.push_back(broker::data(group));
  }

  broker::vector host_ip_addrs;

  for (const auto &ip_addr : getHostIPAddrs()) {
    host_ip_addrs.push_back(broker::data(ip_addr));
  }

  // clang-format off
  broker::zeek::Event message(
    kBrokerEvent_HOST_NEW,

    {
      broker::data(caf::to_string(d->broker_endpoint->node_id())),
      broker::data(d->peer_name),
      broker::data(d->host_identifier),
      joined_group_list,
      broker::data(ZEEK_AGENT_VERSION),
      broker::data(kZeekAgentEdition),
      host_ip_addrs
    }
  );
  // clang-format on

  d->broker_endpoint->publish(kBrokerTopic_ANNOUNCE, message);
}

broker::configuration ZeekConnection::getBrokerConfiguration() {
  auto ca_file_path = getConfig().certificateAuthority();
  auto cert_file_path = getConfig().clientCertificate();
  auto key_file_path = getConfig().clientKey();

  broker::configuration config;

  if (!ca_file_path.empty() && !cert_file_path.empty() &&
      !key_file_path.empty()) {
    config.set("openssl.cafile", ca_file_path);
    config.set("openssl.certificate", cert_file_path);
    config.set("openssl.key", key_file_path);
  }

  return config;
}

Status ZeekConnection::createSubscription(const std::string &topic) {
  if (d->subscriber_map.count(topic) != 0U) {
    return Status::failure(
        "A subscription already exists for the following topic: " + topic);
  }

  auto subscriber = d->broker_endpoint->make_subscriber({topic});
  d->subscriber_map.insert({topic, std::move(subscriber)});

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Subscribed to: " + topic);

  return Status::success();
}

Status ZeekConnection::destroySubscription(const std::string &topic) {
  auto subscriber_it = d->subscriber_map.find(topic);
  if (subscriber_it == d->subscriber_map.end()) {
    return Status::failure("The following topic has not been subscribed to: " +
                           topic);
  }

  auto &subscriber = subscriber_it->second;
  subscriber.remove_topic(topic);

  d->subscriber_map.erase(subscriber_it);
  return Status::success();
}

Status ZeekConnection::getStatusEvents(StatusEventList &status_event_list) {
  status_event_list = {};

  auto status_message_list = d->status_subscriber.poll();
  if (status_message_list.empty()) {
    return Status::success();
  }

  for (const auto &status_message : status_message_list) {
    if (const auto &status = caf::get_if<broker::status>(&status_message)) {
      status_event_list.push_back(status->code());
    }

    if (const auto &error = caf::get_if<broker::error>(&status_message)) {
      std::string message = caf::to_string(error->context()).c_str();
      return Status::failure(message);
    }
  }

  return Status::success();
}

Status
ZeekConnection::computeQueryOutputHash(std::uint64_t &hash,
                                       const IVirtualDatabase::OutputRow &row) {

  hash = 0U;

  auto xxh64_state = createXXH64State();
  if (!xxh64_state) {
    return Status::failure("Failed to create the XXH64 state");
  }

  for (const auto &column_value : row) {
    auto error = XXH64_update(xxh64_state.get(), column_value.name.c_str(),
                              column_value.name.size());

    if (error == XXH_ERROR) {
      return Status::failure("Failed to compute the row hash");
    }

    if (!column_value.data.has_value()) {
      static const std::string kNullColumnValue{"<NULL>"};

      error = XXH64_update(xxh64_state.get(), column_value.name.c_str(),
                           column_value.name.size());

    } else {
      const auto &var = column_value.data.value();

      if (std::holds_alternative<std::string>(var)) {
        const auto &string_value = std::get<std::string>(var);

        error = XXH64_update(xxh64_state.get(), string_value.c_str(),
                             string_value.size());

      } else if (std::holds_alternative<std::int64_t>(var)) {
        auto integer_value = std::get<std::int64_t>(var);

        error = XXH64_update(xxh64_state.get(), &integer_value,
                             sizeof(integer_value));

      } else {
        return Status::failure("Invalid column type");
      }
    }

    if (error == XXH_ERROR) {
      return Status::failure("Failed to compute the row hash");
    }
  }

  hash = XXH64_digest(xxh64_state.get());
  return Status::success();
}

std::string ZeekConnection::computeQueryID(const std::string &response_topic,
                                           const std::string &response_event,
                                           const std::string &cookie) {
  return response_topic + response_event + cookie;
}

Status ZeekConnection::computeDifferentials(
    DifferentialContext &context, DifferentialOutput &output,
    const QueryScheduler::TaskOutput &task_output) {

  output = {};

  // Generate new differential data for this query output
  DifferentialData differential_data;
  for (const auto &row : task_output.query_output) {
    std::uint64_t row_hash = 0U;
    auto status = computeQueryOutputHash(row_hash, row);
    if (!status.succeeded()) {
      return status;
    }

    differential_data.insert({row_hash, row});
  }

  // Look for the old differential data
  auto query_id =
      computeQueryID(task_output.response_topic, task_output.response_event,
                     task_output.cookie);

  auto old_differential_data_it = context.find(query_id);
  if (old_differential_data_it == context.end()) {
    context.insert({query_id, std::move(differential_data)});
    output.added_row_list = task_output.query_output;

    return Status::success();
  }

  auto &old_differential_data = old_differential_data_it->second;

  // Determine what kind of updates we are required to process
  bool process_rows_added{false};
  bool process_rows_removed{false};

  if (task_output.update_type.has_value()) {
    auto update_type = task_output.update_type.value();

    if (update_type == QueryScheduler::Task::UpdateType::Added) {
      process_rows_added = true;

    } else if (update_type == QueryScheduler::Task::UpdateType::Removed) {
      process_rows_removed = true;

    } else if (update_type == QueryScheduler::Task::UpdateType::Both) {
      process_rows_added = true;
      process_rows_removed = true;

    } else {
      return Status::failure("Invalid task update type");
    }
  }

  // Put new rows in the added row list
  if (process_rows_added) {
    for (const auto &new_diff_p : differential_data) {
      const auto &new_row_hash = new_diff_p.first;
      const auto &new_row_output = new_diff_p.second;

      if (old_differential_data.find(new_row_hash) ==
          old_differential_data.end()) {
        output.added_row_list.push_back(new_row_output);
      }
    }
  }

  // Put the rows we lost in the removed row list
  if (process_rows_removed) {
    for (const auto &old_diff_p : old_differential_data) {
      const auto &old_row_hash = old_diff_p.first;
      const auto &old_row_output = old_diff_p.second;

      if (differential_data.find(old_row_hash) == differential_data.end()) {
        output.removed_row_list.push_back(old_row_output);
      }
    }
  }

  // Update the differential data inside the context structure
  std::swap(old_differential_data, differential_data);

  return Status::success();
}

Status
ZeekConnection::scheduledTaskFromZeekEvent(QueryScheduler::Task &task,
                                           const broker::zeek::Event &event) {
  task = {};

  const auto &event_name = event.name();
  if (event_name != kHostSubscribeEvent &&
      event_name != kHostUnsubscribeEvent) {

    return Status::failure(
        "Invalid event type (expected: host_subscribe or host_unsubscribe)");
  }

  task.type = (event.name() == kHostSubscribeEvent)
                  ? QueryScheduler::Task::Type::AddScheduledQuery
                  : QueryScheduler::Task::Type::RemoveScheduledQuery;

  try {
    task.query = getZeekEventQueryString(event);
    task.response_event = getZeekEventResponseEventName(event);
    task.cookie = getZeekEventCookie(event);
    task.response_topic = getZeekEventResponseTopic(event);
    task.interval = getZeekEventInterval(event);

    auto update_type = getZeekEventUpdateType(event);
    if (update_type == "ADDED") {
      task.update_type = QueryScheduler::Task::UpdateType::Added;

    } else if (update_type == "REMOVED") {
      task.update_type = QueryScheduler::Task::UpdateType::Removed;

    } else if (update_type == "BOTH") {
      task.update_type = QueryScheduler::Task::UpdateType::Both;

    } else {
      return Status::failure("Invalid update type for scheduled queries: " +
                             update_type);
    }

    return Status::success();

  } catch (const Status &status) {
    return status;
  }
}

Status
ZeekConnection::oneShotTaskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event) {
  task = {};

  const auto &event_name = event.name();
  if (event_name != kHostExecuteEvent) {
    return Status::failure("Invalid event type (expected: host_execute)");
  }

  try {
    task.type = QueryScheduler::Task::Type::ExecuteQuery;
    task.query = getZeekEventQueryString(event);
    task.response_event = getZeekEventResponseEventName(event);
    task.cookie = getZeekEventCookie(event);
    task.response_topic = getZeekEventResponseTopic(event);

    auto update_type = getZeekEventUpdateType(event);
    if (update_type != "SNAPSHOT") {
      return Status::failure("Invalid update type for one-shot queries: " +
                             update_type);
    }

    return Status::success();

  } catch (const Status &status) {
    return status;
  }
}

Status ZeekConnection::taskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event) {

  const auto &event_name = event.name();

  if (event_name == kHostSubscribeEvent ||
      event_name == kHostUnsubscribeEvent || event_name == kHostExecuteEvent) {

    return scheduledTaskFromZeekEvent(task, event);

  } else {
    task = {};
    return Status::failure("Invalid event name: " + event_name);
  }
}
} // namespace zeek
