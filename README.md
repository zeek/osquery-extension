# Zeek Agent

The *Zeek Agent* is an endpoint monitoring tool for Linux that
reports, by default, socket and process events to
[Zeek](https://zeek.org). Event data is captured from Audit using the
Unix domain socket plugin that comes with Audisp, and is then
presented to Zeek as an SQL database (using SQLite virtual tables
internally).

Zeek-Agent can optionally also interface to
[osquery](https://www.osquery.io), allowing Zeek to access almost all
the endpoint information that it provides (excluding only evented
tables).

Pre-built, statically linked `zeek-agent` packages are available on
the [releases page](https://github.com/zeek/zeek-agent/releases).

On the Zeek side, the [Zeek Agent
Framework](https://github.com/zeek/zeek-agent-framework) provides the
API access Zeek Agents, as well as some default scripts recording
endpoint activity into Zeek logs.

## Documentation

The documentation has been moved to the [Zeek Agent
Wiki](https://github.com/zeek/zeek-agent/wiki), and contains
guides on building, configuring and extending the Zeek Agent project.

For convenience, the build and configuration guides can be accessed from the following links:
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
