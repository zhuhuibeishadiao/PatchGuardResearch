#include "Log.h"

HANDLE g_hLogFile = NULL;

EXTERN_C NTSTATUS LogInitialize()
{
    UNICODE_STRING logFilePathU = {};
    RtlInitUnicodeString(&logFilePathU, L"\\??\\C:\\kLog.log");

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &logFilePathU,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr,
        nullptr);

    IO_STATUS_BLOCK ioStatus = {};
    auto status = ZwCreateFile(
        &g_hLogFile, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &ioStatus,
        nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

EXTERN_C void LogTermination()
{
    if (g_hLogFile)
        ZwClose(g_hLogFile);

    g_hLogFile = NULL;
}

NTSTATUS LogpMakePrefix(_In_ ULONG Level,
    _In_ const char *LogMessage,
    _Out_ char *LogBuffer,
    _In_ size_t LogBufferLength) {

    char const *levelString = nullptr;
    switch (Level) {
    case LOGP_LEVEL_DEBUG:
        levelString = "DBG";
        break;
    case LOGP_LEVEL_INFO:
        levelString = "INF";
        break;
    case LOGP_LEVEL_WARN:
        levelString = "WRN";
        break;
    case LOGP_LEVEL_ERROR:
        levelString = "ERR";
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    auto status = STATUS_SUCCESS;

    char timeBuffer[20] = {};

    TIME_FIELDS timeFields;
    LARGE_INTEGER systemTime, localTime;
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &timeFields);

    status = RtlStringCchPrintfA(timeBuffer, RTL_NUMBER_OF(timeBuffer),
        "%02u:%02u:%02u.%03u\t", timeFields.Hour,
        timeFields.Minute, timeFields.Second,
        timeFields.Milliseconds);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlStringCchPrintfA(
        LogBuffer, LogBufferLength, "%s%s\t%s",
        timeBuffer, levelString,
        LogMessage);

    if(NT_SUCCESS(status))
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", LogBuffer);

    return status;
}

NTSTATUS LogpWriteMessageToFile(
    _In_ const char *Message) {
    IO_STATUS_BLOCK ioStatus = {};
    auto status =
        ZwWriteFile(g_hLogFile, nullptr, nullptr, nullptr, &ioStatus,
            const_cast<char *>(Message),
            static_cast<ULONG>(strlen(Message)), nullptr, nullptr);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = ZwFlushBuffersFile(g_hLogFile, &ioStatus);
    return status;
}

NTSTATUS LogpPut(_In_ const char *Message) {
    auto status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL && !KeAreAllApcsDisabled()) {
        status = LogpWriteMessageToFile(Message);
    }
    return status;
}

EXTERN_C NTSTATUS LogpPrint(_In_ ULONG Level, _In_ const char *Format, ...) 
{
    auto status = STATUS_SUCCESS;

    va_list args;
    va_start(args, Format);
    char logMessage[300];
    status =
        RtlStringCchVPrintfA(logMessage, RTL_NUMBER_OF(logMessage), Format, args);
    va_end(args);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (logMessage[0] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    // A single entry of log should not exceed 512 bytes. See
    // Reading and Filtering Debugging Messages in MSDN for details.
    char message[100 + RTL_NUMBER_OF(logMessage)];
    static_assert(RTL_NUMBER_OF(message) <= 512,
        "One log message should not exceed 512 bytes.");

    status = LogpMakePrefix(Level, logMessage, message,
        RTL_NUMBER_OF(message));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return LogpPut(message);
}

