#pragma once

#include <map>
#include <memory>
#include <vector>

#include <zeek/status.h>

namespace zeek {
/// \brief Audisp socket consumer (interface)
class IAudispConsumer {
public:
  /// \brief SYSCALL record data
  struct SyscallRecordData final {
    /// \brief Supported syscalls
    enum class Type {
      Execve,
      ExecveAt,
      Fork,
      VFork,
      Clone,
      Bind,
      Connect,
      Open,
      OpenAt,
      Create
    };

    /// \brief Event type
    Type type;

    /// \brief Syscall exit code
    std::int64_t exit_code{0};

    /// \brief Process identifier
    std::int64_t process_id{0};

    /// \brief Parent process identifier
    std::int64_t parent_process_id{0};

    /// \brief Whether the syscall has succeeded or not
    bool succeeded{false};

    /// \brief Audit id
    std::int64_t auid{0};

    /// \brief User id
    std::int64_t uid{0};

    /// \brief Effective user id
    std::int64_t euid{0};

    /// \brief Group id
    std::int64_t gid{0};

    /// \brief Effective group id
    std::int64_t egid{0};

    /// \brief Executable path
    std::string exe;

    /// \brief First syscall parameter (raw)
    std::string a0;
  };

  /// \brief EXECVE record data (unprocessed)
  struct RawExecveRecordData final {
    /// \brief Parameter count
    int argc{0};

    /// \brief Parameter list
    std::map<std::string, std::string> argument_list;
  };

  /// \brief EXECVE record data
  struct ExecveRecordData final {
    /// \brief Parameter count
    int argc{0};

    /// \brief parameter list
    std::vector<std::string> argument_list;
  };

  /// \brief PATH record data
  struct PathRecord final {
    /// \brief Path
    std::string path;

    /// \brief File mode
    std::int64_t mode{0};

    /// \brief Owner user id
    std::int64_t ouid{0};

    /// \brief Owner group id
    std::int64_t ogid{0};

    /// \brief File Inode
    std::int64_t inode{0};
  };

  /// \brief A list of PATH records
  using PathRecordData = std::vector<PathRecord>;

  /// \brief SOCKADDR record data
  struct SockaddrRecordData final {
    /// \brief Address family
    std::int64_t family{0};

    /// \brief Port
    std::int64_t port{0};

    /// \brief IP address
    std::string address;
  };

  /// \brief A single Audit event, built from multiple records
  struct AuditEvent final {
    /// \brief SYSCALL record data
    SyscallRecordData syscall_data;

    /// \brief EXECVE record data (optional)
    std::optional<ExecveRecordData> execve_data;

    /// \brief PATH record data (optional)
    std::optional<PathRecordData> path_data;

    /// \brief CWD record data; contains the working directory of the process
    std::optional<std::string> cwd_data;

    /// \brief SOCKADDR record data (optional)
    std::optional<SockaddrRecordData> sockaddr_data;
  };

  /// \brief A list of Audit events
  using AuditEventList = std::vector<AuditEvent>;

  /// \brief A unique_ptr to an IAudispConsumer interface
  using Ref = std::unique_ptr<IAudispConsumer>;

  /// \brief Factory method
  /// \param obj where the created object is stored
  /// \param audisp_socket_path The path to the unix domain socket of Audisp
  /// \return A Status object
  static Status create(Ref &obj, const std::string &audisp_socket_path);

  /// \brief Constructor
  IAudispConsumer() = default;

  /// \brief Destructor
  virtual ~IAudispConsumer() = default;

  /// \brief Call this method in a loop to read and process the Audisp events
  /// \return A Status object
  virtual Status processEvents() = 0;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(AuditEventList &event_list) = 0;

  IAudispConsumer(const IAudispConsumer &other) = delete;
  IAudispConsumer &operator=(const IAudispConsumer &other) = delete;
};
} // namespace zeek
