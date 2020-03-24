#include "configuration.h"
#include "logger.h"
#include "zeekagent.h"

#include <iostream>

#if defined(__linux__) || defined(__APPLE__)
#include <signal.h>

#elif defined(WIN32)
#include <zeek/network.h>

#else
#error Unsupported platform
#endif

std::atomic_bool terminate_agent{false};

#if defined(__linux__) || defined(__APPLE__)
void sigintHandler(int) { terminate_agent = true; }

#elif defined(WIN32)
BOOL WINAPI sigintHandler(DWORD signal) {
  if (signal == CTRL_C_EVENT) {
    terminate_agent = true;
  }

  return true;
}

#else
#error Unsupported platform
#endif

int main() {
  std::cout << "Zeek Agent v" << ZEEK_AGENT_VERSION << "\n";

  zeek::ZeekAgent::Ref zeek_agent;
  auto status = zeek::ZeekAgent::create(zeek_agent);
  if (!status.succeeded()) {
    std::cerr << "Initialization failed: " << status.message() << "\n";
    return 1;
  }

#if defined(__linux__) || defined(__APPLE__)
  struct sigaction signal_action {};
  signal_action.sa_handler = sigintHandler;
  if (sigaction(SIGINT, &signal_action, nullptr) != 0) {
    std::cerr << "Failed to initialize the SIGINT handler\n";
    return 1;
  }

#elif defined(WIN32)
  if (!SetConsoleCtrlHandler(sigintHandler, TRUE)) {
    std::cerr << "Failed to initialize the CTRL+C handler\n";
    return 1;
  }

#else
#error Unsupported platform
#endif

  status = zeek::initializeConfiguration(zeek_agent->virtualDatabase());
  if (!status.succeeded()) {
    std::cerr << "Initialization failed: " << status.message() << "\n";
    return 1;
  }

  status = zeek::initializeLogger(zeek_agent->virtualDatabase());
  if (!status.succeeded()) {
    std::cerr << "Initialization failed: " << status.message() << "\n";
    return 1;
  }

  status = zeek_agent->exec(terminate_agent);

  zeek::deinitializeConfiguration();
  zeek::deinitializeLogger();

  if (!status.succeeded()) {
    std::cerr << "An error has occurred: " << status.message() << "\n";
    return 1;
  }

  return 0;
}
