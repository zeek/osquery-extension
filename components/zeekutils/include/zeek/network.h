#pragma once

#include <cstdint>

#if defined(__linux__) || defined(__APPLE__)
#include <poll.h>
#include <unistd.h>

using SOCKET = int;

#elif defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Winsock2.h>

namespace zeek {
using nfds_t = std::uint32_t;

int poll(struct pollfd fds[], nfds_t nfds, int timeout);
} // namespace zeek

#else
#error Unsupported platform
#endif
