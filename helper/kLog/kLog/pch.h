#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "..\kLogLib\Log.h"

#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)