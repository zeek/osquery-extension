#pragma once

#include <memory>
#include <variant>
#include <vector>

#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief Audisp socket consumer (interface)
class IEndpointSecurityConsumer {
public:
  /// \brief Event data
  struct Event final {
    /// \brief Event header
    struct EventHeader final {
      pid_t process_id{};
      pid_t thread_id{};
    };

    /// \brief Exec event data
    struct ExecEventData final {
      /// \brief Program path
      std::string path;
    };

    /// \brief Fork event data
    struct ForkEventData {};

    /// \brief Event data variant
    using EventData = std::variant<ExecEventData, ForkEventData>;

    /// \brief Event header
    EventHeader header;

    /// \brief Event data
    EventData data;
  };

  /// \brief A list of events
  using EventList = std::vector<Event>;

  /// \brief A unique_ptr to an IEndpointSecurityConsumer
  using Ref = std::unique_ptr<IEndpointSecurityConsumer>;

  /// \brief Factory method
  /// \param obj where the created object is stored
  /// \param logger an initialized logger object
  /// \param configuration an initialized configuration object
  /// \return A Status object
  static Status create(Ref &obj, IZeekLogger &logger,
                       IZeekConfiguration &configuration);

  /// \brief Constructor
  IEndpointSecurityConsumer() = default;

  /// \brief Destructor
  virtual ~IEndpointSecurityConsumer() = default;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(EventList &event_list) = 0;

  IEndpointSecurityConsumer(const IEndpointSecurityConsumer &other) = delete;

  IEndpointSecurityConsumer &
  operator=(const IEndpointSecurityConsumer &other) = delete;
};
} // namespace zeek
