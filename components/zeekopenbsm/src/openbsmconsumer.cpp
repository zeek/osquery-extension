#include "openbsmconsumer.h"
#include "openbsm_utils.h"

#include <chrono>
#include <condition_variable>
#include <ctime>
#include <future>
#include <iomanip>
#include <thread>

namespace zeek {

namespace {
#define AUDIT_PIPE_PATH "/dev/auditpipe"
} // namespace

struct OpenbsmConsumer::PrivateData final {
  PrivateData(IZeekLogger &logger_, IZeekConfiguration &configuration_)
      : logger(logger_), configuration(configuration_) {}

  IZeekLogger &logger;
  IZeekConfiguration &configuration;

  EventList event_list;
  std::mutex event_list_mutex;
  std::condition_variable event_list_cv;

  std::atomic_bool terminate_producer{false};
};

OpenbsmConsumer::OpenbsmConsumer(IZeekLogger &logger,
                                 IZeekConfiguration &configuration)
    : d(new PrivateData(logger, configuration)) {

  // start fetching events from pipe in a separate thread
  std::thread{&OpenbsmConsumer::fetchEventsFromPipe, this}.detach();
}

OpenbsmConsumer::~OpenbsmConsumer() {
  d->terminate_producer = true;
  if (audit_pipe != nullptr) {
    fclose(audit_pipe);
    audit_pipe = nullptr;
  }
  d->event_list_cv.notify_all();
}

Status OpenbsmConsumer::getEvents(EventList &event_list) {
  event_list = {};

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

void OpenbsmConsumer::extractHeader(IOpenbsmConsumer::Event &event,
                                    tokenstr_t tok) {
  switch (tok.id) {
  case AUT_HEADER32:
    event.header.timestamp = tok.tt.hdr32.s;
    if (tok.tt.hdr32.e_type == AUE_CONNECT) {
      event.type = Event::Type::Connect;
    } else if (tok.tt.hdr32.e_type == AUE_BIND) {
      event.type = Event::Type::Bind;
    }
    break;
  case AUT_HEADER64:
    event.header.timestamp = tok.tt.hdr64.s;
    if (tok.tt.hdr64.e_type == AUE_CONNECT) {
      event.type = Event::Type::Connect;
    } else if (tok.tt.hdr64.e_type == AUE_BIND) {
      event.type = Event::Type::Bind;
    }
    break;
  case AUT_HEADER32_EX:
    event.header.timestamp = tok.tt.hdr32_ex.s;
    if (tok.tt.hdr32_ex.e_type == AUE_CONNECT) {
      event.type = Event::Type::Connect;
    } else if (tok.tt.hdr32_ex.e_type == AUE_BIND) {
      event.type = Event::Type::Bind;
    }
    break;
  case AUT_HEADER64_EX:
    event.header.timestamp = tok.tt.hdr64_ex.s;
    if (tok.tt.hdr64_ex.e_type == AUE_CONNECT) {
      event.type = Event::Type::Connect;
    } else if (tok.tt.hdr64_ex.e_type == AUE_BIND) {
      event.type = Event::Type::Bind;
    }
    break;
  }
}

void OpenbsmConsumer::extractSubject(IOpenbsmConsumer::Event &event,
                                     tokenstr_t tok) {

  switch (tok.id) {
  case AUT_SUBJECT32: {
    uint32_t pid = tok.tt.subj32.pid;
    event.header.process_id = pid;
    event.header.path = getPathFromPid(pid);
    event.header.user_id = tok.tt.subj32.euid;
    event.header.group_id = tok.tt.subj32.egid;
    break;
  }
  case AUT_SUBJECT64: {
    uint32_t pid = tok.tt.subj64.pid;
    event.header.process_id = pid;
    event.header.path = getPathFromPid(pid);
    event.header.user_id = tok.tt.subj64.euid;
    event.header.group_id = tok.tt.subj64.egid;
    break;
  }
  case AUT_SUBJECT32_EX: {
    uint32_t pid = tok.tt.subj32_ex.pid;
    event.header.process_id = pid;
    event.header.path = getPathFromPid(pid);
    event.header.user_id = tok.tt.subj32_ex.euid;
    event.header.group_id = tok.tt.subj32_ex.egid;
    break;
  }
  case AUT_SUBJECT64_EX: {
    uint32_t pid = tok.tt.subj64_ex.pid;
    event.header.process_id = pid;
    event.header.path = getPathFromPid(pid);
    event.header.user_id = tok.tt.subj64_ex.euid;
    event.header.group_id = tok.tt.subj64_ex.egid;
    break;
  }
  }
}

void OpenbsmConsumer::extractReturn(IOpenbsmConsumer::Event &event,
                                    tokenstr_t tok) {

  switch (tok.id) {
  case AUT_RETURN32: {
    int error = 0;
    if (au_bsm_to_errno(tok.tt.ret32.status, &error) == 0) {
      if (error == 0) {
        event.header.success = 1;
      } else {
        event.header.success = 0;
      }
    } else
      event.header.success = 0;
    break;
  }
  case AUT_RETURN64: {
    int error = 0;
    if (au_bsm_to_errno(tok.tt.ret64.err, &error) == 0) {
      if (error == 0) {
        event.header.success = 1;
      } else {
        event.header.success = 0;
      }
    } else
      event.header.success = 0;
    break;
  }
  }
}
void OpenbsmConsumer::extractSocketInet(IOpenbsmConsumer::Event &event,
                                        tokenstr_t tok) {

  switch (tok.id) {
  case AUT_SOCKINET32: {
    if (event.type == Event::Type::Bind) {
      event.header.remote_address = "0.0.0.0";
      event.header.remote_port = 0;
      event.header.local_address = getIpFromToken(tok);
      event.header.local_port = ntohs(tok.tt.sockinet_ex32.port);
    } else {
      event.header.remote_address = getIpFromToken(tok);
      event.header.remote_port = ntohs(tok.tt.sockinet_ex32.port);
      event.header.local_address = "0.0.0.0";
      event.header.local_port = 0;
    }
    if (tok.tt.sockinet_ex32.family == 2) {
      event.header.family = 2;
    } else if (tok.tt.sockinet_ex32.family == 26) {
      event.header.family = 10;
    } else {
      event.header.family = 0;
    }

    break;
  }
  case AUT_SOCKINET128: {
    if (event.type == Event::Type::Bind) {
      event.header.remote_address = "0.0.0.0";
      event.header.remote_port = 0;
      event.header.local_address = getIpFromToken(tok);
      event.header.local_port =
          static_cast<std::int64_t>(ntohs(tok.tt.sockinet_ex32.port));
    } else {
      event.header.remote_address = getIpFromToken(tok);
      event.header.remote_port =
          static_cast<std::int64_t>(ntohs(tok.tt.sockinet_ex32.port));
      event.header.local_address = "0.0.0.0";
      event.header.local_port = 0;
    }
    if (tok.tt.sockinet_ex32.family == 2) {
      event.header.family = 2;
    } else if (tok.tt.sockinet_ex32.family == 26) {
      event.header.family = 10;
    } else {
      event.header.family = 0;
    }
    break;
  }
  }
}

Status
OpenbsmConsumer::populateSocketEvent(Event &event,
                                     const std::vector<tokenstr_t> &tokens) {

  for (const auto &tok : tokens) {
    if (tok.id == AUT_SOCKUNIX) {
      // we filter unix sockets out
      continue;
    }
    switch (tok.id) {
    case AUT_HEADER32:
    case AUT_HEADER64:
    case AUT_HEADER32_EX:
    case AUT_HEADER64_EX:
      extractHeader(event, tok);
      break;
    case AUT_SUBJECT32:
    case AUT_SUBJECT64:
    case AUT_SUBJECT32_EX:
    case AUT_SUBJECT64_EX:
      extractSubject(event, tok);
      break;
    case AUT_RETURN32:
    case AUT_RETURN64:
      extractReturn(event, tok);
      break;
    case AUT_SOCKINET32:
    case AUT_SOCKINET128:
      extractSocketInet(event, tok);
      break;
    }
  } // for loop

  return Status::success();
}

Status OpenbsmConsumer::parseMessage() {

  Status status;
  Event event;

  u_char *buffer = nullptr;

  int reclen = au_read_rec(audit_pipe, &buffer);

  if (reclen <= 0) {
    return Status::failure("Could not openbsm fetch message");
  }

  tokenstr_t tok;
  std::vector<tokenstr_t> tokens{};
  tokens.reserve(12);

  auto event_id = 0;
  auto bytesread = 0;
  while (bytesread < reclen) {
    if (au_fetch_tok(&tok, buffer + bytesread, reclen - bytesread) == -1) {
      break;
    }
    switch (tok.id) {
    case AUT_HEADER32:
      event_id = tok.tt.hdr32.e_type;
      break;
    case AUT_HEADER32_EX:
      event_id = tok.tt.hdr32_ex.e_type;
      break;
    case AUT_HEADER64:
      event_id = tok.tt.hdr64.e_type;
      break;
    case AUT_HEADER64_EX:
      event_id = tok.tt.hdr64_ex.e_type;
      break;
    }
    tokens.push_back(tok);
    bytesread += tok.len;
  }
  if (event_filter_list.find(event_id) == event_filter_list.end()) {
    // Return early for unused event IDs.
    return Status::success();
  }

  status = populateSocketEvent(event, tokens);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error, status.message());

  } else {
    std::lock_guard<std::mutex> lock(d->event_list_mutex);
    d->event_list.push_back(std::move(event));
    d->event_list_cv.notify_all();
  }
  return status;
}

Status OpenbsmConsumer::fetchEventsFromPipe() {

  audit_pipe = fopen(AUDIT_PIPE_PATH, "r");
  if (audit_pipe == nullptr) {
    throw Status::failure("The auditpipe couldn't be opened.");
  }
  event_filter_list.insert(AUE_CONNECT);
  event_filter_list.insert(AUE_BIND);
  fd_set fdset;
  struct timeval timeout {};
  timeout.tv_sec = 0;
  timeout.tv_usec = 200000;

  while (!d->terminate_producer) {
    FD_ZERO(&fdset);
    FD_SET(fileno(audit_pipe), &fdset);

    int rc = select(FD_SETSIZE, &fdset, nullptr, nullptr, &timeout);

    if (rc == 0) {
      continue;
    }
    if (rc < 0) {
      if (errno != EINTR) {
        return Status::failure("Auditpipe cannot be read");
      }
      continue;
    }
    parseMessage();
  }
  return Status::success();
}

Status IOpenbsmConsumer::create(Ref &obj, IZeekLogger &logger,
                                IZeekConfiguration &configuration) {
  try {
    obj.reset(new OpenbsmConsumer(logger, configuration));
    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
