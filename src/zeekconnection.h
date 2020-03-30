#pragma once

#include "queryscheduler.h"

#include <memory>
#include <optional>

#ifdef WIN32
#pragma warning(push)
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
#endif

#include <broker/broker.hh>

#ifdef WIN32
#pragma warning(pop)
#endif

#include <zeek/status.h>

namespace zeek {
/// \brief A handler for the connection to the Zeek server
class ZeekConnection final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief A reference to a connection object
  using Ref = std::unique_ptr<ZeekConnection>;

  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param host_identifier The UUID of the system, or the hostname
  ///                        if it was not possible to acquire it
  /// \return A Status object
  static Status create(Ref &obj, const std::string &host_identifier);

  /// \brief Destructor
  ~ZeekConnection();

  /// \brief Joins a new Zeek group
  /// \param name The group name
  /// \return A Status object
  Status joinGroup(const std::string &name);

  /// \brief Leaves an active Zeek group
  /// \param name The group name
  /// \return A Status object
  Status leaveGroup(const std::string &name);

  /// \brief Updates the connection state
  /// \return A Status object
  Status processEvents();

  /// \return Returns the list of queued tasks
  QueryScheduler::TaskQueue getTaskQueue();

  /// \brief Processes the given list of task outputs, dispatching the
  ///        results to the Zeek instance
  /// \param task_output_list A list of task outputs
  /// \return A Status object
  Status processTaskOutputList(QueryScheduler::TaskOutputList task_output_list);

  ZeekConnection(const ZeekConnection &) = delete;
  ZeekConnection &operator=(const ZeekConnection &) = delete;

private:
  /// \brief Constructor
  /// \param host_identifier The UUID of the system, or the hostname
  ///                        if it was not possible to acquire it
  ZeekConnection(const std::string &host_identifier);

  /// \return The broker configuration
  broker::configuration getBrokerConfiguration();

  /// \brief Subscribes to a new broker topic
  /// \param topic The topic name
  /// \return A Status object
  Status createSubscription(const std::string &topic);

  /// \brief Unsubscribes from a broker topic
  /// \param topic The topic name
  /// \return A Status object
  Status destroySubscription(const std::string &topic);

  /// \brief A list of broker status events
  using StatusEventList = std::vector<broker::sc>;

  /// \brief Updates the connection status
  /// \param status_event_list Where the new status list is stored
  /// \return A Status object
  Status getStatusEvents(StatusEventList &status_event_list);

  /// \brief Waits for new events, timing out after 1 second
  /// \param ready This boolean is set to true if there is incoming data
  ///              that can be read
  /// \return A Status object
  Status waitForActivity(bool &ready);

  /// \brief Processes the output for a single task, dispatching results to
  ///        the Zeek instance
  /// \param task_output The task output that needs to be processed
  /// \return A Status object
  Status processTaskOutput(const QueryScheduler::TaskOutput &task_output);

  /// \brief Publishes the given task output message to Zeek
  /// \param trigger The reason this task was run (differential change or
  ///                snapshot)
  /// \param response_topic The output topic
  /// \param response_event The event name
  /// \param cookie The id that identifies this task
  /// \param query_output The query results associated with this task
  void publishTaskOutput(const std::string &trigger,
                         const std::string &response_topic,
                         const std::string &response_event,
                         const std::string &cookie,
                         const IVirtualDatabase::QueryOutput &query_output);

public:
  /// \brief The differential context for a single table, used to calculate
  ///        differential output
  using DifferentialData =
      std::unordered_map<std::uint64_t, IVirtualDatabase::OutputRow>;

  /// \brief The global differentinal context for all tables, used to calculate
  ///        differential output
  using DifferentialContext = std::unordered_map<std::string, DifferentialData>;

  /// \brief Differential output
  struct DifferentialOutput final {
    /// \brief List of added rows
    IVirtualDatabase::QueryOutput added_row_list;

    /// \brief List of removed rows
    IVirtualDatabase::QueryOutput removed_row_list;
  };

  /// \brief Computes a hash that represents the given query output row. Used
  ///        for differentials
  /// \param hash The calculated hash
  /// \param row The row to hash
  /// \return A Status object
  static Status computeQueryOutputHash(std::uint64_t &hash,
                                       const IVirtualDatabase::OutputRow &row);

  /// \brief Computes a unique query ID for the specified task attributes
  /// \param response_topic The response topic of the task
  /// \param response_event The event name of the task
  /// \param cookie The task id
  /// \return A unique task ID
  static std::string computeQueryID(const std::string &response_topic,
                                    const std::string &response_event,
                                    const std::string &cookie);

  /// \brief Computes differentials for the given query output, updating the
  ///        differential context
  /// \param context The differential context, updated on return
  /// \param output The differential output
  /// \param task_output The full task output
  /// \return A Status object
  static Status
  computeDifferentials(DifferentialContext &context, DifferentialOutput &output,
                       const QueryScheduler::TaskOutput &task_output);

  /// \brief Creates a new scheduled task from the given broker event
  /// \param task Where the new task is stored
  /// \param event The Zeek request
  /// \return A Status object
  static Status scheduledTaskFromZeekEvent(QueryScheduler::Task &task,
                                           const broker::zeek::Event &event);

  /// \brief Creates a new ad-hoc task from the given broker event
  /// \param task Where the new task is stored
  /// \param event The Zeek request
  /// \return A Status object
  static Status oneShotTaskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event);

  /// \brief Creates a new ad-hoc or scheduled task, depending on the
  ///        given Zeek event
  /// \param task Where the new task is stored
  /// \param event The Zeek request
  /// \return A Status object
  static Status taskFromZeekEvent(QueryScheduler::Task &task,
                                  const broker::zeek::Event &event);
};
} // namespace zeek
