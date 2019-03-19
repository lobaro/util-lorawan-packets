#pragma once

#ifndef configLOG_LORAWAN_PACKETS
#define configLOG_LORAWAN_PACKETS 1
#endif

#if configLOG_LORAWAN_PACKETS == 1
#define LOG_ERROR(...) lib.api.LogError(__VA_ARGS__)
#define LOG_INFO(...) lib.api.LogInfo(__VA_ARGS__)
#else
#define LOG_ERROR(...) {}
#define LOG_INFO(...) {}
#endif
