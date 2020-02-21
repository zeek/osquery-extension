[Unit]
Description=Zeek Agent (standalone)
After=network.target

[Service]
ExecStart=${CMAKE_INSTALL_PREFIX}/bin/zeek-agent
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target

