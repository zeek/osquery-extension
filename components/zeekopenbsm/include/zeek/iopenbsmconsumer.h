#pragma once

#include <memory>
#include <unistd.h>
#include <variant>
#include <vector>

#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>
#include <zeek/status.h>

namespace zeek {
/// \brief OpenBSM consumer (interface)
class IOpenbsmConsumer {
public:
  /// \brief Event data
  struct Event final {
    /// \brief Event header
    struct Header final {
      /// \brief Event timestamp
      std::uint64_t timestamp{};

      /// \brief Process id
      pid_t process_id{};

      /// \brief User id
      uid_t user_id{};

      /// \brief Group id
      gid_t group_id{};

      /// \brief Program path
      std::string path;

      /// \brief success
      int success;

      /// \brief remote ip address
      std::string remote_address;

      /// \brief remote port number
      int remote_port;

      /// \brief local ip address
      std::string local_address;

      /// \brief local port number
      int local_port;

      /// \brief protocol family
      int family;
    };

    /// \brief Supported event types
    enum class Type { Connect, Bind };

    /// \brief Event type
    Type type;

    /// \brief Event header
    Header header;
  };

  /// \brief A list of events
  using EventList = std::vector<Event>;

  /// \brief A unique_ptr to an IOpenbsmConsumer
  using Ref = std::unique_ptr<IOpenbsmConsumer>;

  /// \brief Factory method
  /// \param obj where the created object is stored
  /// \param logger an initialized logger object
  /// \param configuration an initialized configuration object
  /// \return A Status object
  static Status create(Ref &obj, IZeekLogger &logger,
                       IZeekConfiguration &configuration);

  /// \brief Constructor
  IOpenbsmConsumer() = default;

  /// \brief Destructor
  virtual ~IOpenbsmConsumer() = default;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(EventList &event_list) = 0;

  IOpenbsmConsumer(const IOpenbsmConsumer &other) = delete;

  IOpenbsmConsumer &operator=(const IOpenbsmConsumer &other) = delete;
};
} // namespace zeek
