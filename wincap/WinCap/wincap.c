

#include <ntddk.h>

#include <Ndis.h>
#include <wdf.h>
#include "wincap.h"

#define SIOCTL_TYPE 40000
#define IOCTL_INVERT_NOTIFICATION CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

//The number of bytes in an Ethernet (MAC) address.
#define	ETHER_ADDR_LEN 6

//The number of bytes in the type field.
#define	ETHER_TYPE_LEN 2

#define	ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)

ULONG g_DltNullMode = 0;
/*
* Structure of a DLT_NULL header.
*/
typedef struct _DLT_NULL_HEADER {
	UINT	null_type;
} DLT_NULL_HEADER, *PDLT_NULL_HEADER;

/*
* The length of the combined header.
*/
#define	DLT_NULL_HDR_LEN	sizeof(DLT_NULL_HEADER)

// 
// Callout and sublayer GUIDs
//

// 2D605B3E-C244-4364-86E8-BD81E6C91B6D
DEFINE_GUID(
	WCP_OUTBOUND_IPPACKET_CALLOUT_V4,
	0x2d605b3e,
	0xc244,
	0x4364,
	0x86, 0xe8, 0xbd, 0x81, 0xe6, 0xc9, 0x1b, 0x6d
);
// F935E4CD-9499-4934-824D-8E3726BA4A93
DEFINE_GUID(
	WCP_OUTBOUND_IPPACKET_CALLOUT_V6,
	0xf935e4cd,
	0x9499,
	0x4934,
	0x82, 0x4d, 0x8e, 0x37, 0x26, 0xba, 0x4a, 0x93
);
// ED7E5EB2-6B09-4783-961C-5495EAAD361E
DEFINE_GUID(
	WCP_INBOUND_IPPACKET_CALLOUT_V4,
	0xed7e5eb2,
	0x6b09,
	0x4783,
	0x96, 0x1c, 0x54, 0x95, 0xea, 0xad, 0x36, 0x1e
);
// 21022F40-9578-4C39-98A5-C97B8D834E27
DEFINE_GUID(
	WCP_INBOUND_IPPACKET_CALLOUT_V6,
	0x21022f40,
	0x9578,
	0x4c39,
	0x98, 0xa5, 0xc9, 0x7b, 0x8d, 0x83, 0x4e, 0x27
);

// 2F32C254-A054-469B-B99B-3E8810275A71
DEFINE_GUID(
	WCP_SUBLAYER,
	0x2f32c254,
	0xa054,
	0x469b,
	0xb9, 0x9b, 0x3e, 0x88, 0x10, 0x27, 0x5a, 0x71
);

// 
// Callout driver global variables
//

DEVICE_OBJECT* gWdmDevice;
WDFDEVICE controlDevice;

BOOLEAN captureRunning = FALSE;
BOOLEAN callbacksInitialized = FALSE;

UINT32 g_OutboundIPPacketV4 = 0;
UINT32 g_OutboundIPPacketV6 = 0;
UINT32 g_InboundIPPacketV4 = 0;
UINT32 g_InboundIPPacketV6 = 0;
HANDLE g_InjectionHandle_IPv4 = INVALID_HANDLE_VALUE;
HANDLE g_InjectionHandle_IPv6 = INVALID_HANDLE_VALUE;

_Success_(return)
BOOLEAN
WCP_IsPacketSelfSent(
	_In_ PNET_BUFFER_LIST pNetBufferList,
	_In_ BOOLEAN bIPv4,
	_Out_ BOOLEAN *pbInnerIPv4,
	_Out_ UCHAR *puProto
) {
	NTSTATUS			status = STATUS_SUCCESS;
	NET_BUFFER*			pNetBuffer = 0;
	PVOID				pContiguousData = NULL;
	UCHAR				pPacketData[IPV6_HDR_LEN];
	UCHAR				uProto;



	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
	while (pNetBuffer) {
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			bIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			pPacketData,
			1,
			0);
		if (!pContiguousData) {
			status = STATUS_UNSUCCESSFUL;
			return FALSE;
		} else {
			uProto = bIPv4 ? ((PIP_HEADER)pContiguousData)->ip_Protocol : ((PIP6_HEADER)pContiguousData)->ip6_CTL.ip6_HeaderCtl.ip6_NextHeader;
			*puProto = uProto;
			if (uProto == IPPROTO_WINCAP_LOOPBACK) {
				*pbInnerIPv4 = bIPv4;

				return TRUE;
			}
			else {

				return FALSE;
			}
		}

		//pNetBuffer = pNetBuffer->Next;
	}

	return FALSE;
}

BOOLEAN
WCP_IsICMPProtocolUnreachablePacket(
	_In_ PNET_BUFFER_LIST pNetBufferList
) {
	NTSTATUS			status = STATUS_SUCCESS;
	NET_BUFFER*			pNetBuffer = 0;
	PVOID				pContiguousData = NULL;
	UCHAR				pPacketData[IP_HDR_LEN + ICMP_HDR_LEN];
	PIP_HEADER			pIPHeader;
	PICMP4_HEADER		pICMPHeader;



	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
	while (pNetBuffer) {
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			IP_HDR_LEN + ICMP_HDR_LEN,
			pPacketData,
			1,
			0);
		if (!pContiguousData) {
			status = STATUS_UNSUCCESSFUL;

			return FALSE;
		}
		else {
			pIPHeader = (PIP_HEADER)pContiguousData;
			pICMPHeader = (PICMP4_HEADER)((PUCHAR)pContiguousData + IP_HDR_LEN);
			if (((*((PUCHAR)(&pIPHeader->ip_Src)) == 0x7F && *((PUCHAR)(&pIPHeader->ip_Dst)) == 0x7F) || (pIPHeader->ip_Src == pIPHeader->ip_Dst)) &&
				pICMPHeader->icmp_Type == ICMP_TYPE_DEST_UNREACH && pICMPHeader->icmp_Code == ICMP_CODE_PROT_UNREACH) {
				return TRUE;
			}
			else {
				return FALSE;
			}
		}

		//pNetBuffer = pNetBuffer->Next;
	}


	return FALSE;
}

VOID WCP_NetworkInjectionComplete(
	_In_ VOID* pContext,
	_Inout_ NET_BUFFER_LIST* pNetBufferList,
	_In_ BOOLEAN dispatchLevel
) {
	UNREFERENCED_PARAMETER(dispatchLevel);
	UNREFERENCED_PARAMETER(pContext);


	if (pNetBufferList->Status != STATUS_SUCCESS) {
	}

	FwpsFreeCloneNetBufferList(pNetBufferList, 0);


	return;
}

NTSTATUS WCP_ShareClonedNetBufferList(PNET_BUFFER_LIST pClonedNetBufferList, BOOLEAN bSelfSent) {

	/*
	* Sends a network-package to an open IOCTL-request.
	* If the buffer of the request is too small for the package, a partial package is sent and 
	* the rest of the network-package is ignored.
	* If there are no IOCTL-requests available the network-package is discarded
	*/
	
	PNET_BUFFER_LIST	pRcvNetBufList;
	PUCHAR				pSrc, pDst;
	ULONG				BytesRemaining; // at pDst
	PMDL				pMdl;
	ULONG				BytesAvailable;
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	WDFREQUEST			wdfIoQueueRequest;
	ULONG				bytesCopied = 0, totalLength;
	//PVOID				pContiguousData = NULL;
	//NET_BUFFER*			pNetBuffer = 0;
	PINVERTED_DEVICE_CONTEXT devContext;

	UNREFERENCED_PARAMETER(bSelfSent);

	/*
	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pClonedNetBufferList);
	while (pNetBuffer) {
		pContiguousData = NdisGetDataBuffer(pNetBuffer,
			bytesRetreatedEthernet,
			pPacketData,
			1,
			0);
		if (!pContiguousData)
	*/

	devContext = InvertedGetContextFromDevice(controlDevice);

	status = WdfIoQueueRetrieveNextRequest(devContext->NotificationQueue, &wdfIoQueueRequest);
	if (!NT_SUCCESS(status)) {
		// this happens everytime we don't have enough IOCTLs. Printing this slows windows down too much.
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfIoQueueRetrieveNextRequest failed\n");
		return status;
	}
	
	
	status = WdfRequestRetrieveOutputWdmMdl(wdfIoQueueRequest, &pMdl);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfRequestRetrieveOutputWdmMdl failed\n");
		return status;
	}

	pDst = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority | MdlMappingNoExecute);
	if (pDst == NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MmGetSystemAddressForMdlSafe failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		return status;
	}


	pRcvNetBufList = pClonedNetBufferList;
	totalLength = BytesRemaining = MmGetMdlByteCount(pMdl);
	pMdl = pRcvNetBufList->FirstNetBuffer->MdlChain;

	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "totalLength %ld\n", totalLength);

	while (BytesRemaining && (pMdl != NULL)) {
		pSrc = NULL;
		NdisQueryMdl(pMdl, &pSrc, &BytesAvailable, NormalPagePriority | MdlMappingNoExecute);
		if (pSrc == NULL) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NdisQueryMdl failed for MDL %p\n", pMdl);
			break;
		}

		if (BytesAvailable) {
			ULONG BytesToCopy = (BytesAvailable < BytesRemaining) ? BytesAvailable : BytesRemaining;
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "data: %s\n", pSrc);
			NdisMoveMemory(pDst, pSrc, BytesToCopy);
			BytesRemaining -= BytesToCopy;
			pDst += BytesToCopy;
		}

		NdisGetNextMdl(pMdl, &pMdl);
	}


	bytesCopied = totalLength - BytesRemaining;

	//sub queue count. the queue count is currently not used
	InterlockedExchangeAdd(&devContext->QueueCount, -1);
	//WdfRequestCompleteWithInformation(wdfIoQueueRequest, STATUS_SUCCESS, devContext->QueueCount);
	WdfRequestCompleteWithInformation(wdfIoQueueRequest, STATUS_SUCCESS, bytesCopied);

	return status;
}

//
// Callout driver functions
//

#if(NTDDI_VERSION >= NTDDI_WIN7)

/* ++

This is the classifyFn function for the Transport (v4 and v6) callout.
packets (inbound or outbound) are ueued to the packet queue to be processed
by the worker thread.

-- */
void
WCP_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
)

#else

void
WCP_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
)

#endif

{
	//POPEN_INSTANCE GroupOpen;
	//POPEN_INSTANCE		TempOpen;
	NTSTATUS			status = STATUS_SUCCESS;
	UINT32				ipHeaderSize = 0;
	UINT32				bytesRetreated = 0;
	UINT32				bytesRetreatedEthernet = 0;
	BOOLEAN				bIPv4;
	BOOLEAN				bInnerIPv4;
	BOOLEAN				bInbound;
	BOOLEAN				bSelfSent = FALSE;
	UCHAR				uIPProto;
	BOOLEAN				bICMPProtocolUnreachable = FALSE;
	//PVOID				pContiguousData = NULL;
	NET_BUFFER*			pNetBuffer = 0;
	//UCHAR				pPacketData[ETHER_HDR_LEN];
	PNET_BUFFER_LIST	pNetBufferList = (NET_BUFFER_LIST*)layerData;
	COMPARTMENT_ID		compartmentID = UNSPECIFIED_COMPARTMENT_ID;
	FWPS_PACKET_INJECTION_STATE injectionState = FWPS_PACKET_INJECTION_STATE_MAX;

#if(NTDDI_VERSION >= NTDDI_WIN7)
	UNREFERENCED_PARAMETER(classifyContext);
#endif
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Make the default action.
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	// Filter out fragment packets and reassembled packets.
	if (inMetaValues->currentMetadataValues & FWP_CONDITION_FLAG_IS_FRAGMENT) {
		return;
	}
#if(NTDDI_VERSION >= NTDDI_VISTASP1)
	if (inMetaValues->currentMetadataValues & FWP_CONDITION_FLAG_IS_REASSEMBLED) {
		return;
	}
#endif



	// Get the packet protocol (IPv4 or IPv6) and the direction (Inbound or Outbound).
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4) {
		bIPv4 = TRUE;
	}
	else if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6) {
		bIPv4 = FALSE;
	}
	else {
		bIPv4 = FALSE;
	}

	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6) {
		bInbound = FALSE;
	}
	else if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 || inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6) {
		bInbound = TRUE;
	}
	else {
		bInbound = FALSE;
	}

	if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) {
		ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	injectionState = FwpsQueryPacketInjectionState(bIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
		pNetBufferList,
		NULL);
	//
	// We don't re-inspect packets that we've inspected earlier.
	//
	if (injectionState == FWPS_PACKET_INJECTED_BY_SELF ||
		injectionState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF) {
		return;
	}

	// Inbound: Initial offset is at the Transport Header, so retreat the size of the Ethernet Header and IP Header.
	// Outbound: Initial offset is at the IP Header, so just retreat the size of the Ethernet Header.
	// We retreated the packet in two phases: 1) retreat the IP Header (if has), 2) clone the packet and retreat the Ethernet Header.
	// We must NOT retreat the Ethernet Header on the original packet, or this will lead to BAD_POOL_CALLER Bluescreen.
	bytesRetreated = bInbound ? ipHeaderSize : 0;

	status = NdisRetreatNetBufferListDataStart(pNetBufferList,
		bytesRetreated,
		0,
		NULL,
		NULL);

	if (status != STATUS_SUCCESS) {
		return;
	}

	bSelfSent = bInbound ? WCP_IsPacketSelfSent(pNetBufferList, bIPv4, &bInnerIPv4, &uIPProto) : FALSE;

	if (bInbound && bIPv4 && !bSelfSent && uIPProto == IPPROTO_ICMP) {
		bICMPProtocolUnreachable = WCP_IsICMPProtocolUnreachablePacket(pNetBufferList);
		if (bICMPProtocolUnreachable) {
			goto Exit_WSK_IP_Retreated;
		}
	}

	if (bSelfSent) {
		NdisAdvanceNetBufferListDataStart(pNetBufferList,
			bIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			FALSE,
			0);
	}

	// Here if this NBL is sent by ourself, we will clone it starting from IP header and inject it into Network Layer send path.
	if (bSelfSent) {
		PNET_BUFFER_LIST pClonedNetBufferList_Injection;
		status = FwpsAllocateCloneNetBufferList(pNetBufferList, NULL, NULL, 0, &pClonedNetBufferList_Injection);
		if (status != STATUS_SUCCESS) {

			goto Exit_WSK_IP_Retreated;
		}

		if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
			FWPS_METADATA_FIELD_COMPARTMENT_ID)) {
			compartmentID = (COMPARTMENT_ID)inMetaValues->compartmentId;
		}

		// This cloned NBL will be freed in WCP_NetworkInjectionComplete function.
		status = FwpsInjectNetworkSendAsync(bInnerIPv4 ? g_InjectionHandle_IPv4 : g_InjectionHandle_IPv6,
			NULL,
			0,
			compartmentID,
			pClonedNetBufferList_Injection,
			WCP_NetworkInjectionComplete,
			NULL);
		if (status != STATUS_SUCCESS) {

			FwpsFreeCloneNetBufferList(pClonedNetBufferList_Injection, 0);
			goto Exit_WSK_IP_Retreated;
		}

		// We have successfully re-inject the cloned NBL, so remove this one.
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
		classifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;
	}

	// We clone this NBL again, for packet reading operation.
	PNET_BUFFER_LIST pClonedNetBufferList;
	status = FwpsAllocateCloneNetBufferList(pNetBufferList, NULL, NULL, 0, &pClonedNetBufferList);
	if (status != STATUS_SUCCESS) {

		goto Exit_WSK_IP_Retreated;
	}

	bytesRetreatedEthernet = g_DltNullMode ? DLT_NULL_HDR_LEN : ETHER_HDR_LEN;
	status = NdisRetreatNetBufferListDataStart(pClonedNetBufferList,
		bytesRetreatedEthernet,
		0,
		0,
		0);
	if (status != STATUS_SUCCESS) {
		bytesRetreatedEthernet = 0;

		goto Exit_Packet_Cloned;
	}

	//pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pClonedNetBufferList);

	if (captureRunning) {
		//send data to usermode
		WCP_ShareClonedNetBufferList(pClonedNetBufferList, bSelfSent);
	}

	// Advance the offset back to the original position.
	NdisAdvanceNetBufferListDataStart(pClonedNetBufferList,
		bytesRetreatedEthernet,
		FALSE,
		0);

Exit_Packet_Cloned:
	FwpsFreeCloneNetBufferList(pClonedNetBufferList, 0);

Exit_WSK_IP_Retreated:
	if (bSelfSent) {
		status = NdisRetreatNetBufferListDataStart(pNetBufferList,
			bIPv4 ? IP_HDR_LEN : IPV6_HDR_LEN,
			0,
			NULL,
			NULL);
	}

	//Exit_IP_Retreated:
	NdisAdvanceNetBufferListDataStart(pNetBufferList,
		bytesRetreated,
		FALSE,
		0);


	return;
}

NTSTATUS
WCP_NetworkNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}


NTSTATUS WCP_AddFilter(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey
) {

	NTSTATUS status = STATUS_SUCCESS;

	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION filterConditions[1] = { 0 };
	UINT conditionIndex;

	filter.layerKey = *layerKey;
	filter.displayData.name = L"Network WinCap Filter (Outbound)";
	filter.displayData.description = L"WinCap inbound/outbound network traffic";

	filter.action.calloutKey = *calloutKey;
	filter.filterCondition = filterConditions;
	filter.subLayerKey = WCP_SUBLAYER;
	filter.rawContext = 0;
	conditionIndex = 0;

	filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0x2;
	filter.filterCondition = NULL;

	/*filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0x5;
	filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
	filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_NONE_SET;
	filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
	filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
	conditionIndex++;
	*/
	/*
	else if (iFlag == 1)
	{
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0x4;
	filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
	filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_ALL_SET;
	filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
	filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_FRAGMENT;
	conditionIndex++;
	}
	#if(NTDDI_VERSION >= NTDDI_VISTASP1)
	else if (iFlag == 2)
	{
	filter.action.type = FWP_ACTION_PERMIT;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0x3;
	filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
	filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_ALL_SET;
	filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
	filterConditions[conditionIndex].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_REASSEMBLED;
	conditionIndex++;
	}
	#endif
	else if (iFlag == 3)
	{
	filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = 0x2;
	filter.filterCondition = NULL;
	}

	// 	else if (iFlag == 1)
	// 	{
	// 		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
	// 		filter.weight.type = FWP_UINT8;
	// 		filter.weight.uint8 = 0x4;
	// 		filterConditions[conditionIndex].fieldKey = FWPM_CONDITION_FLAGS;
	// 		filterConditions[conditionIndex].matchType = FWP_MATCH_FLAGS_NONE_SET;
	// 		filterConditions[conditionIndex].conditionValue.type = FWP_UINT32;
	// 		filterConditions[conditionIndex].conditionValue.uint32 = FWPS_METADATA_FIELD_FRAGMENT_DATA | FWP_CONDITION_FLAG_IS_REASSEMBLED;
	// 		conditionIndex++;
	// 	}
	else
	{

	return status;
	}
	*/
	filter.numFilterConditions = conditionIndex;

	status = FwpmFilterAdd(
		gWdmDevice,
		&filter,
		NULL,
		NULL);

	return status;
}

NTSTATUS WCP_RegisterCallout(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey,
	_Inout_ void* deviceObject,
	_Out_ UINT32* calloutId
) {
	/* ++

	This function registers callouts and filters that intercept transport
	traffic at the following layers --

	FWPM_LAYER_INBOUND_IPPACKET_V4
	FWPM_LAYER_INBOUND_IPPACKET_V6
	FWPM_LAYER_OUTBOUND_IPPACKET_V4
	FWPM_LAYER_OUTBOUND_IPPACKET_V4_DISCARD

	-- */


	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = WCP_NetworkClassify;
	sCallout.notifyFn = WCP_NetworkNotify;

	status = FwpsCalloutRegister(
		deviceObject,
		&sCallout,
		calloutId
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpsCalloutRegister failed with status: 0x%0x\n", status);
		goto Exit;
	}
	calloutRegistered = TRUE;

	displayData.name = L"WinCap Network Callout";
	displayData.description = L"WinCap inbound/outbound network traffic";

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = displayData;
	mCallout.applicableLayer = *layerKey;

	status = FwpmCalloutAdd(
		gWdmDevice,
		&mCallout,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmCalloutAdd failed with status: 0x%0x\n", status);
		goto Exit;
	}

	status = WCP_AddFilter(layerKey, calloutKey);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_AddFilter failed with status: 0x%0x\n", status);
		goto Exit;
	}
	/*
	status = WCP_AddFilter(layerKey, calloutKey, 1);
	if (!NT_SUCCESS(status))
	{
	goto Exit;
	}
	#if(NTDDI_VERSION >= NTDDI_VISTASP1)
	status = WCP_AddFilter(layerKey, calloutKey, 2);
	if (!NT_SUCCESS(status))
	{
	goto Exit;
	}
	#endif
	status = WCP_AddFilter(layerKey, calloutKey, 3);
	if (!NT_SUCCESS(status))
	{
	goto Exit;
	}
	*/

Exit:

	if (!NT_SUCCESS(status)) {
		if (calloutRegistered) {
			FwpsCalloutUnregisterById(*calloutId);
			*calloutId = 0;
		}
	}


	return status;
}

NTSTATUS WCP_RegisterCallouts(
	_Inout_ void* deviceObject
) {
	/* ++

	This function registers dynamic callouts and filters that intercept
	transport traffic at ALE AUTH_CONNECT/AUTH_RECV_ACCEPT and
	INBOUND/OUTBOUND transport layers.

	Callouts and filters will be removed during DriverUnload.

	-- */
	NTSTATUS status = STATUS_SUCCESS;
	FWPM_SUBLAYER NPFSubLayer;

	BOOLEAN engineOpened = FALSE;
	BOOLEAN inTransaction = FALSE;

	FWPM_SESSION session = { 0 };

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&gWdmDevice
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmEngineOpen failed\n");
		goto Exit;
	}
	engineOpened = TRUE;

	status = FwpmTransactionBegin(gWdmDevice, 0);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}
	inTransaction = TRUE;

	RtlZeroMemory(&NPFSubLayer, sizeof(FWPM_SUBLAYER));

	NPFSubLayer.subLayerKey = WCP_SUBLAYER;
	NPFSubLayer.displayData.name = L"WinCap Sub-Layer";
	NPFSubLayer.displayData.description = L"Sub-Layer for use by WinCap callouts";
	NPFSubLayer.flags = 0;
	NPFSubLayer.weight = 0; // must be less than the weight of 
							// FWPM_SUBLAYER_UNIVERSAL to be
							// compatible with Vista's IpSec
							// implementation.

	status = FwpmSubLayerAdd(gWdmDevice, &NPFSubLayer, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmSubLayerAdd failed\n");
		goto Exit;
	}

	//if (isV4)
{
		status = WCP_RegisterCallout(
			&FWPM_LAYER_OUTBOUND_IPPACKET_V4,
			&WCP_OUTBOUND_IPPACKET_CALLOUT_V4,
			deviceObject,
			&g_OutboundIPPacketV4
		);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV4_1 failed with status: 0x%0x\n", status);
			goto Exit;
		}

		status = WCP_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V4,
			&WCP_INBOUND_IPPACKET_CALLOUT_V4,
			deviceObject,
			&g_InboundIPPacketV4
		);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV4_2 with status: 0x%0x\n", status);
			goto Exit;
		}
	}
	//else
	{
		status = WCP_RegisterCallout(
			&FWPM_LAYER_OUTBOUND_IPPACKET_V6,
			&WCP_OUTBOUND_IPPACKET_CALLOUT_V6,
			deviceObject,
			&g_OutboundIPPacketV6
		);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV6 with status: 0x%0x\n", status);
			goto Exit;
		}

		status = WCP_RegisterCallout(
			&FWPM_LAYER_INBOUND_IPPACKET_V6,
			&WCP_INBOUND_IPPACKET_CALLOUT_V6,
			deviceObject,
			&g_InboundIPPacketV6
		);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV6 failed with status: 0x%0x\n", status);
			goto Exit;
		}
	}

	status = FwpmTransactionCommit(gWdmDevice);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmTransactionCommit failed with status: 0x%0x\n", status);
		goto Exit;
	}
	inTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(status)) {
		if (inTransaction) {
			FwpmTransactionAbort(gWdmDevice);
			_Analysis_assume_lock_not_held_(gWdmDevice); // Potential leak if "FwpmTransactionAbort" fails
		}
		if (engineOpened) {
			FwpmEngineClose(gWdmDevice);
			gWdmDevice = INVALID_HANDLE_VALUE;
		}
	}


	return status;
}

void WCP_UnregisterCallouts() {


	if (gWdmDevice != INVALID_HANDLE_VALUE) {
		FwpmEngineClose(gWdmDevice);
		gWdmDevice = INVALID_HANDLE_VALUE;

		if (g_OutboundIPPacketV4) {
			FwpsCalloutUnregisterById(g_OutboundIPPacketV4);
		}
		if (g_OutboundIPPacketV6) {
			FwpsCalloutUnregisterById(g_OutboundIPPacketV6);
		}
		if (g_InboundIPPacketV4) {
			FwpsCalloutUnregisterById(g_InboundIPPacketV4);
		}
		if (g_InboundIPPacketV6) {
			FwpsCalloutUnregisterById(g_InboundIPPacketV6);
		}
	}


}

NTSTATUS WCP_InitInjectionHandles() {
	/* ++

	Open injection handles (IPv4 and IPv6) for use with the various injection APIs.

	injection handles will be removed during DriverUnload.

	-- */

	NTSTATUS status = STATUS_SUCCESS;

	status = FwpsInjectionHandleCreate(AF_INET,
		FWPS_INJECTION_TYPE_NETWORK,
		&g_InjectionHandle_IPv4);
	if (status != STATUS_SUCCESS) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpsInjectionHandleCreate failed with status: 0x%0x\n", status);
		return status;
	}

	status = FwpsInjectionHandleCreate(AF_INET6,
		FWPS_INJECTION_TYPE_NETWORK,
		&g_InjectionHandle_IPv6);
	if (status != STATUS_SUCCESS){
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpsInjectionHandleCreate failed with status: 0x%0x\n", status);
		return status;
	}


	return status;
}

NTSTATUS
WCP_FreeInjectionHandles() {
	/* ++

	Free injection handles (IPv4 and IPv6).

	-- */
	NTSTATUS status = STATUS_SUCCESS;


	if (g_InjectionHandle_IPv4 != INVALID_HANDLE_VALUE) {
		status = FwpsInjectionHandleDestroy(g_InjectionHandle_IPv4);

		if (status != STATUS_SUCCESS) {
			return status;
		}

		g_InjectionHandle_IPv4 = INVALID_HANDLE_VALUE;
	}

	if (g_InjectionHandle_IPv6 != INVALID_HANDLE_VALUE) {
		status = FwpsInjectionHandleDestroy(g_InjectionHandle_IPv6);

		if (status != STATUS_SUCCESS) {
			return status;
		}

		g_InjectionHandle_IPv6 = INVALID_HANDLE_VALUE;
	}


	return status;
}


_Function_class_(EVT_WDF_DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_max_(PASSIVE_LEVEL)
void
WCP_DriverUnload(
	IN WDFDRIVER driver
) {

	UNREFERENCED_PARAMETER(driver);

	WCP_UnregisterCallouts();
	WCP_FreeInjectionHandles();


}

VOID
WCP_FileCreate(
	IN WDFDEVICE            device,
	IN WDFREQUEST			request,
	IN WDFFILEOBJECT        fileObject
) {
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(fileObject);
	UNREFERENCED_PARAMETER(device);

	WdfRequestComplete(request, status);

	return;
}

VOID
WCP_FileClose(
	IN WDFFILEOBJECT    fileObject
) {
	UNREFERENCED_PARAMETER(fileObject);
	return;
}

VOID WCP_Shutdown(WDFDEVICE Device) {
	UNREFERENCED_PARAMETER(Device);
	return;
}

VOID
WCP_IoDeviceControl(
	IN WDFQUEUE         queue,
	IN WDFREQUEST       request,
	IN size_t           outputBufferLength,
	IN size_t           inputBufferLength,
	IN ULONG            ioControlCode
) {
	PINVERTED_DEVICE_CONTEXT devContext;
	NTSTATUS status;
	ULONG_PTR info;

	UNREFERENCED_PARAMETER(outputBufferLength);
	UNREFERENCED_PARAMETER(inputBufferLength);

	devContext = InvertedGetContextFromDevice(WdfIoQueueGetDevice(queue));

	status = STATUS_INVALID_PARAMETER;
	info = 0;

	switch (ioControlCode) {
	case IOCTL_INVERT_NOTIFICATION:
		if (outputBufferLength < sizeof(LONG)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "OutputBufferLength too small\n");
			break;
		}
		status = WdfRequestForwardToIoQueue(request, devContext->NotificationQueue);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfRequestForwardToIoQueue failed\n");
			break;
		}

		//increase the queue count by 1
		InterlockedExchangeAdd(&devContext->QueueCount, 1);
		// the request keeps pending, that's why we return
		return;

	case IOCTL_START_CAPTURE:
		if (!callbacksInitialized) {
			callbacksInitialized = TRUE;
			status = WCP_InitInjectionHandles();
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_InitInjectionHandles failed\n");
				break;
			}
			status = WCP_RegisterCallouts(gWdmDevice);
		}
		captureRunning = TRUE;
		break;
	case IOCTL_STOP_CAPTURE:
		captureRunning = FALSE;
		break;
	default:

		//
		// The specified I/O control code is unrecognized by this driver.
		//
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	WdfRequestComplete(request, status);
}


NTSTATUS
WCP_DeviceAdd(
	IN WDFDRIVER driver,
	IN PWDFDEVICE_INIT deviceInit
) {
	NTSTATUS						status;
	WDF_OBJECT_ATTRIBUTES			attributes;
	WDF_IO_QUEUE_CONFIG				ioQueueConfig;
	WDF_FILEOBJECT_CONFIG			fileConfig;
	//WDFDEVICE						controlDevice;
	PINVERTED_DEVICE_CONTEXT		devContext;
	DECLARE_CONST_UNICODE_STRING(ntDeviceName, L"\\Device\\WinCap");
	DECLARE_CONST_UNICODE_STRING(symbolicLinkName, L"\\DosDevices\\WinCap");


	UNREFERENCED_PARAMETER(driver);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&attributes, INVERTED_DEVICE_CONTEXT);

	WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);

	status = WdfDeviceInitAssignName(deviceInit, &ntDeviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfDeviceInitAssignName failed\n");
		goto Exit;
	}

	WdfControlDeviceInitSetShutdownNotification(deviceInit,
		WCP_Shutdown,
		WdfDeviceShutdown);

	WDF_FILEOBJECT_CONFIG_INIT(
		&fileConfig,
		WCP_FileCreate,
		WCP_FileClose,
		WDF_NO_EVENT_CALLBACK // not interested in Cleanup
	);

	WdfDeviceInitSetFileObjectConfig(deviceInit,
		&fileConfig,
		WDF_NO_OBJECT_ATTRIBUTES);

	status = WdfDeviceCreate(&deviceInit,
		&attributes,
		&controlDevice);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfDeviceCreate failed\n");
		goto Exit;
	}

	devContext = InvertedGetContextFromDevice(controlDevice);
	devContext->QueueCount = 0;

	status = WdfDeviceCreateSymbolicLink(controlDevice, &symbolicLinkName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfDeviceCreateSymbolicLink failed\n");
		goto Exit;
	}

	// for the requests, multiple requests are allowed
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);
	ioQueueConfig.EvtIoDeviceControl = WCP_IoDeviceControl;
	ioQueueConfig.PowerManaged = WdfFalse;

	status = WdfIoQueueCreate(controlDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		WDF_NO_HANDLE
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfIoQueueDispatchParallel-WdfIoQueueCreate failed\n");
		return(status);
	}

	WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig, WdfIoQueueDispatchManual);
	ioQueueConfig.PowerManaged = WdfFalse;

	status = WdfIoQueueCreate(controlDevice,
		&ioQueueConfig,
		WDF_NO_OBJECT_ATTRIBUTES,
		&devContext->NotificationQueue);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfIoQueueDispatchManual-WdfIoQueueCreate failed\n");
		return(status);
	}

	WdfControlFinishInitializing(controlDevice);

	//retrieve the wdm device for the Callout-Functions
	gWdmDevice = WdfDeviceWdmGetDeviceObject(controlDevice);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "added WinCap driver\n");
	return STATUS_SUCCESS;

Exit:
	if (deviceInit != NULL) {
		WdfDeviceInitFree(deviceInit);
	}
	return status;
}

NTSTATUS
DriverEntry(
	IN OUT PDRIVER_OBJECT driverObject,
	IN PUNICODE_STRING registryPath
) {
	NTSTATUS						status;
	WDF_DRIVER_CONFIG				config;
	WDFDRIVER						hDriver;
	PWDFDEVICE_INIT					pInit = NULL;
	WDF_OBJECT_ATTRIBUTES			attributes;

	// Request NX Non-Paged Pool when available
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	WDF_DRIVER_CONFIG_INIT(
		&config,
		WDF_NO_EVENT_CALLBACK // This is a non-pnp driver.
	);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = WCP_DriverUnload;

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);

	status = WdfDriverCreate(driverObject,
		registryPath,
		&attributes,
		&config,
		&hDriver);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfDriverCreate failed\n");
		return status;
	}

	pInit = WdfControlDeviceInitAllocate(
		hDriver,
		&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R
	);
	if (pInit == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfControlDeviceInitAllocate failed\n");
		return status;
	}	

	status = WCP_DeviceAdd(hDriver, pInit);
	if (!NT_SUCCESS(status)) {
		goto Exit;
	}


Exit:

	if (!NT_SUCCESS(status)) {
		if (gWdmDevice != NULL) {
			WCP_UnregisterCallouts();
		}
	}

	return status;
};