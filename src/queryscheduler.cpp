#include "queryscheduler.h"
#include "logger.h"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

namespace zeek {
namespace {
Status querySchedulerThread(QueryScheduler &query_scheduler,
                            std::atomic_bool &terminate) {
  while (!terminate) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto status = query_scheduler.processEvents();
    if (!status.succeeded()) {
      getLogger().logMessage(IZeekLogger::Severity::Error,
                             "The query scheduler has returned an error: " +
                                 status.message());
    }
  }

  return Status::success();
}
} // namespace

struct QueryScheduler::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_)
      : virtual_database(virtual_database_) {}

  IVirtualDatabase &virtual_database;

  std::unique_ptr<std::thread> thread;
  std::atomic_bool terminate{false};

  TaskQueue task_queue;
  std::mutex task_queue_mutex;

  std::map<std::string, Task> scheduled_task_list;
  std::vector<std::pair<std::uint64_t, std::string>> schedule;

  std::mutex task_output_list_mutex;
  std::vector<TaskOutput> task_output_list;
};

Status QueryScheduler::create(Ref &obj, IVirtualDatabase &virtual_database) {
  try {
    obj.reset();

    auto ptr = new QueryScheduler(virtual_database);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

QueryScheduler::~QueryScheduler() { stop(); }

void QueryScheduler::processTaskQueue(TaskQueue task_queue) {
  std::lock_guard<std::mutex> lock(d->task_queue_mutex);

  // clang-format off
  d->task_queue.insert(
    d->task_queue.end(),
    std::make_move_iterator(task_queue.begin()),
    std::make_move_iterator(task_queue.end())
  );
  // clang-format on
}

Status QueryScheduler::processEvents() {
  TaskQueue task_queue;

  {
    std::lock_guard<std::mutex> lock(d->task_queue_mutex);

    task_queue = std::move(d->task_queue);
    d->task_queue = {};
  }

  auto current_timestamp = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  for (auto &task : task_queue) {
    auto task_key = task.query + task.response_topic + task.cookie;

    if (task.type == Task::Type::ExecuteQuery) {
      getLogger().logMessage(IZeekLogger::Severity::Information,
                             "Executing one-shot query: " + task.query);

      auto status = executeTask(task);
      if (!status.succeeded()) {
        getLogger().logMessage(
            IZeekLogger::Severity::Error,
            "The query scheduler could not execute a one-shot task: " +
                status.message());
      }

    } else if (task.type == Task::Type::AddScheduledQuery) {
      auto task_it = d->scheduled_task_list.find(task_key);
      if (task_it != d->scheduled_task_list.end()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "Not scheduling duplicate query: " + task.query);

        continue;
      }

      getLogger().logMessage(
          IZeekLogger::Severity::Information,
          "A new query has been scheduled: " + task.query + " (every " +
              std::to_string(task.interval.value()) + " seconds)");

      auto query_timestamp = task.interval.value() + current_timestamp;

      d->scheduled_task_list.insert({task_key, std::move(task)});
      d->schedule.push_back(std::make_pair(query_timestamp, task_key));

    } else if (task.type == Task::Type::RemoveScheduledQuery) {
      auto task_it = d->scheduled_task_list.find(task_key);
      if (task_it == d->scheduled_task_list.end()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "Failed to remove scheduled query (not found)");

        continue;
      }

      d->scheduled_task_list.erase(task_it);

      // clang-format off
      auto schedule_it = std::find_if(
        d->schedule.begin(),
        d->schedule.end(),

        [task_key](std::pair<std::uint64_t, std::string> &pair) -> bool {
          return pair.second == task_key;
        }
      );
      // clang-format on

      if (schedule_it != d->schedule.end()) {
        d->schedule.erase(schedule_it);
      }
    }
  }

  for (auto schedule_it = d->schedule.begin();
       schedule_it != d->schedule.end();) {

    auto &task_timestamp = schedule_it->first;
    const auto &task_key = schedule_it->second;

    auto task_it = d->scheduled_task_list.find(task_key);
    if (task_it == d->scheduled_task_list.end()) {
      schedule_it = d->schedule.erase(schedule_it);
      continue;
    }

    const auto &task = task_it->second;

    if (task_timestamp <= current_timestamp) {
      task_timestamp = current_timestamp + task.interval.value();

      getLogger().logMessage(IZeekLogger::Severity::Debug,
                             "Running scheduled query: " + task.query);

      auto status = executeTask(task);
      if (!status.succeeded()) {
        getLogger().logMessage(
            IZeekLogger::Severity::Error,
            "The query scheduler could not execute a scheduled task: " +
                status.message());
      }
    }

    ++schedule_it;
  }

  return Status::success();
}

QueryScheduler::TaskOutputList QueryScheduler::getTaskOutputList() {
  TaskOutputList task_output_list;

  {
    std::lock_guard<std::mutex> lock(d->task_output_list_mutex);

    task_output_list = std::move(d->task_output_list);
    d->task_output_list = {};
  }

  return task_output_list;
}

Status QueryScheduler::start() {
  try {
    d->thread = std::make_unique<std::thread>(
        querySchedulerThread, std::ref(*this), std::ref(d->terminate));

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");
  }
}

void QueryScheduler::stop() {
  if (!d->thread) {
    return;
  }

  d->terminate = true;

  d->thread->join();
  d->thread.reset();
}

QueryScheduler::QueryScheduler(IVirtualDatabase &virtual_database)
    : d(new PrivateData(virtual_database)) {}

Status QueryScheduler::executeTask(const Task &task) {
  TaskOutput task_output;
  task_output.response_topic = task.response_topic;
  task_output.response_event = task.response_event;
  task_output.update_type = task.update_type;
  task_output.cookie = task.cookie;

  auto status = d->virtual_database.query(task_output.query_output, task.query);
  if (!status.succeeded()) {
    return Status::failure(status.message() + ". Query: " + task.query);
  }

  {
    std::lock_guard<std::mutex> lock(d->task_output_list_mutex);
    d->task_output_list.push_back(std::move(task_output));
  }

  return Status::success();
}
} // namespace zeek
