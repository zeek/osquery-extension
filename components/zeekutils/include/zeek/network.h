#pragma once

#include <cstdint>

#if defined(__linux__) || defined(__APPLE__)
#include <poll.h>
#include <sys/select.h>
#include <unistd.h>

#elif defined(WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <Winsock2.h>

#else
#error Unsupported platform
#endif
