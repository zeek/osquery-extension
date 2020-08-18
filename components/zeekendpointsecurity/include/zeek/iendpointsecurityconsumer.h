#pragma once

#include <memory>
#include <variant>
#include <vector>

#include <zeek/izeekconfiguration.h>
#include <zeek/izeeklogger.h>

#include <unistd.h>

namespace zeek {
/// \brief EndpointSecurity consumer (interface)
class IEndpointSecurityConsumer {
public:
  /// \brief Event data
  struct Event final {
    /// \brief Event header
    struct Header final {
      /// \brief Event timestamp
      std::uint64_t timestamp{};

      /// \brief Current parent process id
      pid_t parent_process_id{};

      /// \brief Original parent process id (before reparenting)
      pid_t orig_parent_process_id{};

      /// \brief Process id
      pid_t process_id{};

      /// \brief User id
      uid_t user_id{};

      /// \brief Group id
      gid_t group_id{};

      /// \brief True if this is an Apple-signed binary
      bool platform_binary{false};

      /// \brief Signing identfier
      std::string signing_id;

      /// \brief Team identifier
      std::string team_id;

      /// \brief Codesign hash
      std::string cdhash;

      /// \brief Program path
      std::string path;

      /// \brief File path
      std::string file_path;
    };

    /// \brief Supported event types
    enum class Type { Fork, Exec, Open, Create };

    /// \brief Exec event data
    struct ExecEventData final {
      /// \brief Command line arguments
      std::vector<std::string> argument_list;
    };

    /// \brief Event type
    Type type;

    /// \brief Event header
    Header header;

    /// \brief Exec event data
    std::optional<ExecEventData> opt_exec_event_data;
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
