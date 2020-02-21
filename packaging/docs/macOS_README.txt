In order to install the Zeek Agent service:

Standalone version
  /bin/launchctl load /Library/LaunchDaemons/com.corelight.zeek-agent.plist

osquery version
  /bin/launchctl load /Library/LaunchDaemons/com.corelight.zeek-agent-osquery.plist

To remove the service, simply use "unload" instead.

