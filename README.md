# Zeek Agent

The *Zeek Agent* is an endpoint monitoring tool for Linux and macOS that
reports, by default, file, socket, and process events to
[Zeek](https://zeek.org). On Linux, event data is captured from [Linux
Audit](https://linux.die.net/man/8/auditd) using the Unix domain socket plugin
that comes with [Audisp](https://linux.die.net/man/8/audispd). On macOS,
Zeek Agent leverages [Endpoint
Security](https://developer.apple.com/documentation/endpointsecurity) framework
to capture file and process events while to collect socket events Zeek Agent
uses [OpenBSM](http://www.trustedbsd.org/openbsm.html).  Collected event data
from endpoint is stored in an SQL database (using SQLite virtual tables
internally) on the host. Events from this database are later fetched by Zeek
using scheduled queries.

Zeek Agent can optionally also interface to [osquery](https://www.osquery.io),
allowing Zeek to access almost all the endpoint information that it provides
(excluding only event tables).

Pre-built, statically linked `zeek-agent` packages are available on
the [releases page](https://github.com/zeek/zeek-agent/releases).

On the Zeek side, the [Zeek Agent
Framework](https://github.com/zeek/zeek-agent-framework) provides the
API access Zeek Agents, as well as some default scripts recording
endpoint activity into Zeek logs.

## Documentation

The documentation has been moved to the [Zeek Agent
Wiki](https://github.com/zeek/zeek-agent/wiki), and contains
guides on building, configuring, and extending the Zeek Agent project.

For convenience, use the following links to build and configure Zeek Agent:
- [Build Guide](https://github.com/zeek/zeek-agent/wiki/Build-Guide)
- [Configuration Guide](https://github.com/zeek/zeek-agent/wiki/Configuration-Guide)

## History

Zeek Agent supersedes an [earlier osquery
extension](https://github.com/zeek/zeek-osquery) for Zeek that focused
on providing osquery's tables to Zeek. Zeek Agent provides all the
same functionality, but can operate independent from osquery as well.
We plan to further extend the events/tables that the agent provides
natively.

## License

Zeek Agent comes with a BSD license, allowing for free use with
virtually no restrictions. You can find it in
[LICENSE](https://github.com/zeek/LICENSE).
