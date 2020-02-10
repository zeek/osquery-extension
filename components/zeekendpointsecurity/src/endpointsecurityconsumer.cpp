#include "endpointsecurityconsumer.h"

#include <array>
#include <condition_variable>
#include <mutex>

#include <EndpointSecurity/EndpointSecurity.h>

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
}

Status EndpointSecurityConsumer::getEvents(EventList &event_list) {
  event_list = {};

  std::unique_lock<std::mutex> lock(d->event_list_mutex);

  if (d->event_list_cv.wait_for(lock, std::chrono::seconds(1U)) ==
      std::cv_status::no_timeout) {
    event_list = std::move(d->event_list);
    d->event_list = {};
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
EndpointSecurityConsumer::processExecNotification(Event &event,
                                                  const void *message_ptr) {
  event = {};

  const auto &message = *static_cast<const es_message_t *>(message_ptr);

  Event new_event;
  new_event.header.process_id = 0;
  new_event.header.thread_id = 0;

  Event::ExecEventData event_data;
  event_data.path = message.event.exec.target->executable->path.data;
  new_event.data = std::move(event_data);

  event = std::move(new_event);
  return Status::success();
}

Status
EndpointSecurityConsumer::processForkNotification(Event &event,
                                                  const void *message_ptr) {
  event = {};

  const auto &message = *static_cast<const es_message_t *>(message_ptr);
  static_cast<void>(message);

  Event new_event;
  new_event.header.process_id = 0;
  new_event.header.thread_id = 0;

  Event::ForkEventData event_data;
  new_event.data = std::move(event_data);

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
