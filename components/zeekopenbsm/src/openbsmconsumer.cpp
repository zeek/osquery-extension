#include "openbsmconsumer.h"
#include "openbsm_utils.h"

#include <chrono>
#include <condition_variable>
#include <ctime>
#include <errno.h>
#include <future>
#include <iomanip>
#include <thread>

namespace zeek {

namespace {
constexpr char AUDIT_PIPE_PATH[] = "/dev/auditpipe";
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
  event_filter_list.insert(AUE_CONNECT);
  event_filter_list.insert(AUE_BIND);
  std::thread{&OpenbsmConsumer::fetchEventsFromPipe, this}.detach();
}

OpenbsmConsumer::~OpenbsmConsumer() { d->terminate_producer = true; }

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

Status OpenbsmConsumer::extractHeader(IOpenbsmConsumer::Event &event,
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
  return Status::success();
}

Status OpenbsmConsumer::extractSubject(IOpenbsmConsumer::Event &event,
                                       tokenstr_t tok) {

  Status status;
  switch (tok.id) {
  case AUT_SUBJECT32: {
    uint32_t pid = tok.tt.subj32.pid;
    event.header.process_id = pid;
    status = getPathFromPid(pid, event.header.path);
    event.header.user_id = tok.tt.subj32.euid;
    event.header.group_id = tok.tt.subj32.egid;
    break;
  }
  case AUT_SUBJECT64: {
    uint32_t pid = tok.tt.subj64.pid;
    event.header.process_id = pid;
    status = getPathFromPid(pid, event.header.path);
    event.header.user_id = tok.tt.subj64.euid;
    event.header.group_id = tok.tt.subj64.egid;
    break;
  }
  case AUT_SUBJECT32_EX: {
    uint32_t pid = tok.tt.subj32_ex.pid;
    event.header.process_id = pid;
    status = getPathFromPid(pid, event.header.path);
    event.header.user_id = tok.tt.subj32_ex.euid;
    event.header.group_id = tok.tt.subj32_ex.egid;
    break;
  }
  case AUT_SUBJECT64_EX: {
    uint32_t pid = tok.tt.subj64_ex.pid;
    event.header.process_id = pid;
    status = getPathFromPid(pid, event.header.path);
    event.header.user_id = tok.tt.subj64_ex.euid;
    event.header.group_id = tok.tt.subj64_ex.egid;
    break;
  }
  }
  return status;
}

Status OpenbsmConsumer::extractReturn(IOpenbsmConsumer::Event &event,
                                      tokenstr_t tok) {
  u_char ret = 0;
  switch (tok.id) {
  case AUT_RETURN32:
    ret = tok.tt.ret32.status;
    break;
  case AUT_RETURN64:
    ret = tok.tt.ret64.err;
    break;
  }

  int error = 0;
  if (au_bsm_to_errno(ret, &error) == 0) {
    if (error == 0) {
      event.header.success = 1;
    } else {
      event.header.success = 0;
    }
  } else
    event.header.success = 0;
  return Status::success();
}

Status OpenbsmConsumer::extractSocketInet(IOpenbsmConsumer::Event &event,
                                          tokenstr_t tok) {

  switch (tok.id) {
  case AUT_SOCKINET32:
  case AUT_SOCKINET128: {
    switch (event.type) {
    case Event::Type::Bind: {
      event.header.remote_address = "";
      event.header.remote_port = 0;
      auto status =
          getIpFromToken(tok.tt.sockinet_ex32, event.header.local_address);
      if (!status.succeeded()) {
        return status;
      }
      event.header.local_port = ntohs(tok.tt.sockinet_ex32.port);
      break;
    }
    case Event::Type::Connect: {
      auto status =
          getIpFromToken(tok.tt.sockinet_ex32, event.header.remote_address);
      if (!status.succeeded()) {
        return status;
      }
      event.header.remote_port = ntohs(tok.tt.sockinet_ex32.port);
      event.header.local_address = "";
      event.header.local_port = 0;
      break;
    }
    default:
      return Status::failure("unhandled event type");
    }
    if (tok.tt.sockinet_ex32.family == AF_INET) {
      event.header.family = AF_INET;
    } else if (tok.tt.sockinet_ex32.family == 26) {
      event.header.family = 10;
    } else {
      event.header.family = 0;
    }
    break;
  }
  }
  return Status::success();
}

Status
OpenbsmConsumer::populateSocketEvent(Event &event,
                                     const std::vector<tokenstr_t> &tokens) {

  Status status = Status::success();
  for (const auto &tok : tokens) {
    switch (tok.id) {
    case AUT_HEADER32:
    case AUT_HEADER64:
    case AUT_HEADER32_EX:
    case AUT_HEADER64_EX:
      status = extractHeader(event, tok);
      break;
    case AUT_SUBJECT32:
    case AUT_SUBJECT64:
    case AUT_SUBJECT32_EX:
    case AUT_SUBJECT64_EX:
      status = extractSubject(event, tok);
      break;
    case AUT_RETURN32:
    case AUT_RETURN64:
      status = extractReturn(event, tok);
      break;
    case AUT_SOCKINET32:
    case AUT_SOCKINET128:
      status = extractSocketInet(event, tok);
      break;
    }
    if (!status.succeeded()) {
      return status;
    }
  }
  return status;
}

void OpenbsmConsumer::parseMessage() {

  u_char *buffer = nullptr;

  int reclen = au_read_rec(audit_pipe, &buffer);

  if (reclen <= 0) {
    d->logger.logMessage(IZeekLogger::Severity::Error,
                         "Cannot read openbsm message: " +
                             std::string(strerror(errno)));
    return;
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
    case AUT_SOCKUNIX:
      // if current record of tokens contains unix socket just return
      return;
    }
    tokens.push_back(tok);
    bytesread += tok.len;
  }
  if (event_filter_list.find(event_id) == event_filter_list.end()) {
    // Return early for unused event IDs.
    return;
  }

  Event event;
  auto status = populateSocketEvent(event, tokens);

  if (!status.succeeded()) {
    d->logger.logMessage(IZeekLogger::Severity::Error, status.message());
  } else {
    std::lock_guard<std::mutex> lock(d->event_list_mutex);
    d->event_list.push_back(std::move(event));
    d->event_list_cv.notify_all();
  }
}

void OpenbsmConsumer::fetchEventsFromPipe() {

  audit_pipe = fopen(AUDIT_PIPE_PATH, "r");
  if (audit_pipe == nullptr) {
    throw Status::failure("Cannot open auditpipe: " +
                          std::string(strerror(errno)));
  }

  fd_set fdset;

  timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 200'000;

  while (!d->terminate_producer) {
    FD_ZERO(&fdset);
    FD_SET(fileno(audit_pipe), &fdset);

    int rc = select(FD_SETSIZE, &fdset, nullptr, nullptr, &timeout);

    if (rc == 0) {
      continue;
    }
    if (rc < 0) {
      if (errno != EINTR) {
        d->logger.logMessage(IZeekLogger::Severity::Error,
                             "Cannot read auditpipe: " +
                                 std::string(strerror(errno)));
      }
      continue;
    }
    parseMessage();
  }
  fclose(audit_pipe);
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
