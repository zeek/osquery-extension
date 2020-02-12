#include "endpointsecurityconsumer.h"

#include <array>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>

namespace zeek {
struct EndpointSecurityConsumer::PrivateData final {
  PrivateData(IZeekLogger &logger_, IZeekConfiguration &configuration_)
      : logger(logger_), configuration(configuration_) {}

  IZeekLogger &logger;
  IZeekConfiguration &configuration;

  es_client_t *es_client{nullptr};

  EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;
};

EndpointSecurityConsumer::~EndpointSecurityConsumer() {
  es_unsubscribe_all(d->es_client);
  es_delete_client(d->es_client);

  d->event_list_cv.notify_all();
}

Status EndpointSecurityConsumer::getEvents(EventList &event_list) {
  event_list = {};

  std::this_thread::sleep_for(std::chrono::seconds(1U));

  {
    std::unique_lock<std::mutex> lock(d->event_list_mutex);

    if (d->event_list_cv.wait_for(lock, std::chrono::seconds(1U)) ==
        std::cv_status::no_timeout) {

      event_list = std::move(d->event_list);
      d->event_list = {};
    }
  }

  return Status::success();
}

EndpointSecurityConsumer::EndpointSecurityConsumer(
    IZeekLogger &logger, IZeekConfiguration &configuration)
    : d(new PrivateData(logger, configuration)) {

  auto new_client_error = es_new_client(
      &d->es_client, ^(es_client_t *client, const es_message_t *message) {
        static_cast<void>(client);
        if (message == nullptr) {
          return;
        }

        endpointSecurityCallback(message);
      });

  // clang-format off
  switch (new_client_error) {
  case ES_NEW_CLIENT_RESULT_SUCCESS:
    break;

  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
    throw Status::failure("Communication with the Endpoint Security subsystem failed.");

  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
    throw Status::failure("The attempt to create a new client contained one or more invalid arguments.");

  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
    throw Status::failure("The caller isn’t properly entitled to connect to Endpoint Security.");

  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
    throw Status::failure("The caller isn’t permitted to connect to Endpoint Security.");

  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
    throw Status::failure("The caller isn’t running as root.");

  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
    throw Status::failure("Too many clients connected to Endpoint Security");
  }
  // clang-format on

  auto clear_cache_error = es_clear_cache(d->es_client);

  // clang-format off
  switch (clear_cache_error) {
  case ES_CLEAR_CACHE_RESULT_SUCCESS:
    break;

  case ES_CLEAR_CACHE_RESULT_ERR_INTERNAL:
    throw Status::failure("Communication with the Endpoint Security system failed.");

  case ES_CLEAR_CACHE_RESULT_ERR_THROTTLE:
    throw Status::failure("Clearing the cache failed because the rate of calls was too high.");
  }
  // clang-format on

  std::array<es_event_type_t, 2> event_list = {ES_EVENT_TYPE_NOTIFY_EXEC,
                                               ES_EVENT_TYPE_NOTIFY_FORK};

  if (es_subscribe(d->es_client, event_list.data(), event_list.size()) !=
      ES_RETURN_SUCCESS) {

    throw Status::failure(
        "Failed to subscribe to the Endpoint Security events.");
  }
}

void EndpointSecurityConsumer::endpointSecurityCallback(
    const void *message_ptr) {

  const auto &message = *static_cast<const es_message_t *>(message_ptr);

  Status status;
  Event event;
  if (message.event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
    status = processExecNotification(event, message_ptr);

  } else if (message.event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
    status = processForkNotification(event, message_ptr);
  }

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error, status.message());

  } else {
    std::lock_guard<std::mutex> lock(d->event_list_mutex);
    d->event_list.push_back(std::move(event));

    d->event_list_cv.notify_all();
  }
}

Status
EndpointSecurityConsumer::initializeEventHeader(Event::Header &event_header,
                                                const void *message_ptr) {

  const auto &message = *static_cast<const es_message_t *>(message_ptr);

  std::optional<std::reference_wrapper<es_process_t>> process_ref;
  if (message.event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
    process_ref = std::ref(*message.event.exec.target);

  } else if (message.event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
    process_ref = std::ref(*message.event.fork.child);

  } else {
    return Status::failure("Unrecognized event type");
  }

  auto &process = process_ref.value().get();
  event_header.timestamp = std::time(nullptr);
  event_header.parent_process_id = process.ppid;
  event_header.orig_parent_process_id = process.original_ppid;
  event_header.process_id = audit_token_to_pid(process.audit_token);
  event_header.user_id = audit_token_to_euid(process.audit_token);
  event_header.group_id = audit_token_to_egid(process.audit_token);
  event_header.platform_binary = process.is_platform_binary;

  event_header.signing_id.assign(process.signing_id.data,
                                 process.signing_id.length);

  event_header.team_id.assign(process.team_id.data, process.team_id.length);

  event_header.path.assign(process.executable->path.data,
                           process.executable->path.length);

  std::stringstream buffer;
  for (const auto &b : process.cdhash) {
    buffer << std::setfill('0') << std::setw(2) << std::hex
           << static_cast<int>(b);
  }

  event_header.cdhash = buffer.str();

  return Status::success();
}

Status
EndpointSecurityConsumer::processExecNotification(Event &event,
                                                  const void *message_ptr) {
  event = {};

  Event new_event;
  new_event.type = Event::Type::Exec;

  auto status = initializeEventHeader(new_event.header, message_ptr);
  if (!status.succeeded()) {
    return status;
  }

  const auto &message = *static_cast<const es_message_t *>(message_ptr);
  Event::ExecEventData exec_data;

  auto argument_count = es_exec_arg_count(&message.event.exec);
  for (auto argument_index = 0U; argument_index < argument_count;
       ++argument_index) {

    auto current_arg = es_exec_arg(&message.event.exec, argument_index);

    exec_data.argument_list.push_back(
        std::string(current_arg.data, current_arg.length));
  }

  new_event.opt_exec_event_data = std::move(exec_data);

  event = std::move(new_event);
  return Status::success();
}

Status
EndpointSecurityConsumer::processForkNotification(Event &event,
                                                  const void *message_ptr) {
  event = {};

  Event new_event;
  new_event.type = Event::Type::Fork;

  auto status = initializeEventHeader(new_event.header, message_ptr);
  if (!status.succeeded()) {
    return status;
  }

  event = std::move(new_event);
  return Status::success();
}

Status IEndpointSecurityConsumer::create(Ref &obj, IZeekLogger &logger,
                                         IZeekConfiguration &configuration) {
  try {
    obj.reset(new EndpointSecurityConsumer(logger, configuration));
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
