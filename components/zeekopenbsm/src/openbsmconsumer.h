#pragma once

#include <bsm/libbsm.h>
#include <set>
#include <thread>
#include <vector>
#include <zeek/iopenbsmconsumer.h>
#include <zeek/status.h>

namespace zeek {
class OpenbsmConsumer final : public IOpenbsmConsumer {
public:
  /// \brief Destructor
  ~OpenbsmConsumer() override;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  Status getEvents(EventList &event_list) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;
  /// audit pipe handle
  FILE *audit_pipe{nullptr};

  /// list of subscribed events
  std::set<size_t> subscribed_event_ids;

  /// producer thread object
  std::thread producer_thread;

  /// \brief Constructor
  OpenbsmConsumer(IZeekLogger &logger, IZeekConfiguration &configuration);

  /// \brief extract header from openbsm token and populate event
  static Status extractHeader(Event &event, tokenstr_t tok);
  /// \brief extract subject from openbsm token and populate event
  static Status extractSubject(Event &event, tokenstr_t tok);
  /// \brief extract return from openbsm token and populate event
  static Status extractReturn(Event &event, tokenstr_t tok);
  /// \brief extract socket-inet from openbsm token and populate event
  static Status extractSocketInet(Event &event, tokenstr_t tok);

public:
  friend class IOpenbsmConsumer;

  void fetchRecordsFromAuditPipe();
  static Status populateEventFromTokens(Event &event,
                                        const std::vector<tokenstr_t> &tokens);
  void parseRecordIntoTokens();
};
} // namespace zeek
