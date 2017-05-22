/*
This file is responsible for sharing the packet data with the usermode
-- */

#include <ntddk.h>
#include <fwpsk.h>

#include "share.h"

NTSTATUS shareClonedNetBufferList(PNET_BUFFER_LIST clonedNetBufferList, BOOLEAN isOutbound) {
	NTSTATUS status = STATUS_SUCCESS;

	NET_BUFFER* pNetBuffer;
	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(clonedNetBufferList);

	while (pNetBuffer) {
		ULONG length = pNetBuffer->DataLength;
		if (isOutbound) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Sending outbound package with the length: %lu\n", length);
		} else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Receiving inbound package with the length: %lu\n", length);
		}
		pNetBuffer = pNetBuffer->Next;
	}
	return status;
}
