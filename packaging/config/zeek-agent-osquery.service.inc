[Unit]
Description=Zeek Agent (osquery enabled)
After=network.target

[Service]
ExecStart=${CMAKE_INSTALL_PREFIX}/bin/zeek-agent-osquery
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target

