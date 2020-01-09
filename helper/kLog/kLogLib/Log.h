#ifndef _LOG_H_
#define _LOG_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#define LOGP_LEVEL_DEBUG 0
#define LOGP_LEVEL_INFO 1
#define LOGP_LEVEL_WARN 2
#define LOGP_LEVEL_ERROR 3

#define LOGF_DEBUG(format, ...) \
  LogpPrint(LOGP_LEVEL_DEBUG, (format), __VA_ARGS__)
#define LOGF_INFO(format, ...) \
  LogpPrint(LOGP_LEVEL_INFO, (format), __VA_ARGS__)
#define LOGF_WARN(format, ...) \
  LogpPrint(LOGP_LEVEL_WARN, (format), __VA_ARGS__)
#define LOGF_ERROR(format, ...) \
  LogpPrint(LOGP_LEVEL_ERROR, (format), __VA_ARGS__)

NTSTATUS LogpPrint(_In_ ULONG Level, _In_ const char *Format, ...);

NTSTATUS LogInitialize();

void LogTermination();

#ifdef __cplusplus
}
#endif

#endif