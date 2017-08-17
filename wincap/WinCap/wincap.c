

#include <ntddk.h>

#include <Ndis.h>
#include <wdf.h>
#include "wincap.h"

#define SIOCTL_TYPE 40000
#define IOCTL_INVERT_NOTIFICATION CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)

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



VOID WCP_NetworkInjectionComplete(
	_In_ VOID* pContext,
	_Inout_ NET_BUFFER_LIST* pNetBufferList,
	_In_ BOOLEAN dispatchLevel
) {
	UNREFERENCED_PARAMETER(dispatchLevel);
	UNREFERENCED_PARAMETER(pContext);

	// unused because we don't clone netbufferlists

	if (pNetBufferList->Status != STATUS_SUCCESS) {
	}

	FwpsFreeCloneNetBufferList(pNetBufferList, 0);


	return;
}

NTSTATUS WCP_ShareNetBufferList(PACKET_INFO* packetInfo) {

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
	PINVERTED_DEVICE_CONTEXT devContext;

	devContext = InvertedGetContextFromDevice(controlDevice);

	status = WdfIoQueueRetrieveNextRequest(devContext->NotificationQueue, &wdfIoQueueRequest);
	if (!NT_SUCCESS(status)) {
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WdfIoQueueRetrieveNextRequest failed (dropping package, need more IOCTLs)\n");
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


	totalLength = BytesRemaining = MmGetMdlByteCount(pMdl);

	// ----------- write packet info

	if (BytesRemaining < 41) {
		// buffer is too small for packet info
		goto Exit;
	}

	// is inbound?
	NdisMoveMemory(pDst, &packetInfo->Inbound, 1);
	BytesRemaining -= 1;
	pDst += 1;

	// is ipv4?
	UCHAR isIpv4 = packetInfo->AddressFamily == AF_INET ? 1 : 0;
	NdisMoveMemory(pDst, &isIpv4, 1);
	BytesRemaining -= 1;
	pDst += 1;

	// write src & target ip
	NdisZeroMemory(pDst, 16 * 2); // zero memory for the length of 2x ipv6 addresses
	if (isIpv4) {
		// source IP
		NdisMoveMemory(pDst, &packetInfo->SrcIp.AsUInt32, 4);
		BytesRemaining -= 16;
		pDst += 16;

		// target IP
		NdisMoveMemory(pDst, &packetInfo->DstIp.AsUInt32, 4);
		BytesRemaining -= 16;
		pDst += 16;
	}
	else {
		// source IP
		NdisMoveMemory(pDst, packetInfo->SrcIp.AsUInt8, 16);
		BytesRemaining -= 16;
		pDst += 16;

		// target IP
		NdisMoveMemory(pDst, packetInfo->DstIp.AsUInt8, 16);
		BytesRemaining -= 16;
		pDst += 16;
	}

	// write port
	NdisMoveMemory(pDst, &packetInfo->Port, 2);
	BytesRemaining -= 2;
	pDst += 2;

	// write protocol
	NdisMoveMemory(pDst, &packetInfo->Protocol, 1);
	BytesRemaining -= 1;
	pDst += 1;

	// write process ID (not implemented yet)
	UINT32 buf = 0;
	NdisMoveMemory(pDst, &buf, 4);
	BytesRemaining -= 4;
	pDst += 4;

	// ----------- fill the remaining buffer with packet data

	pRcvNetBufList = packetInfo->NetBufferList;
	pMdl = pRcvNetBufList->FirstNetBuffer->MdlChain;
	while (BytesRemaining && (pMdl != NULL)) {
		pSrc = NULL;
		NdisQueryMdl(pMdl, &pSrc, &BytesAvailable, NormalPagePriority | MdlMappingNoExecute);
		if (pSrc == NULL) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NdisQueryMdl failed for MDL %p\n", pMdl);
			break;
		}

		if (BytesAvailable) {
			ULONG BytesToCopy = (BytesAvailable < BytesRemaining) ? BytesAvailable : BytesRemaining;
			NdisMoveMemory(pDst, pSrc, BytesToCopy);
			BytesRemaining -= BytesToCopy;
			pDst += BytesToCopy;
		}

		NdisGetNextMdl(pMdl, &pMdl);
	}

Exit:
	bytesCopied = totalLength - BytesRemaining;

	//sub queue count. the queue count is currently not used
	InterlockedExchangeAdd(&devContext->QueueCount, -1);
	//WdfRequestCompleteWithInformation(wdfIoQueueRequest, STATUS_SUCCESS, devContext->QueueCount);
	WdfRequestCompleteWithInformation(wdfIoQueueRequest, STATUS_SUCCESS, bytesCopied);

	return status;
}

void WCP_InboundCallout(
	__in const FWPS_INCOMING_VALUES          *inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	__inout_opt void                         *layerData,
	__in_opt const void                      *classifyContext,
	__in const FWPS_FILTER                   *filter,
	__in UINT64                               flowContext,
	__out FWPS_CLASSIFY_OUT                  *classifyOut)
{

	if (!captureRunning) {
		return;
	}

	UINT32           headerSize = 0;
	NET_BUFFER_LIST *netBufferList = (NET_BUFFER_LIST*)layerData;
	PACKET_INFO      packetInfo = { 0 };

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	

	// Permit the packet to continue
	if (classifyOut && (classifyOut->rights == FWPS_RIGHT_ACTION_WRITE) &&
		(classifyOut->actionType != FWP_ACTION_BLOCK)) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
	}

	if (!netBufferList) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "received empty inbound layerData\n");
		return;
	}

	// Get the connection ID, address family, port, and protocol
	packetInfo.ConnectionId = FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) ?
		inMetaValues->transportEndpointHandle & UINT32_MAX : UINT32_MAX;

	if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
		packetInfo.AddressFamily = AF_INET;
		packetInfo.Port = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
		packetInfo.Protocol = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ipv4 port: %d\n", packetInfo.Port);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ipv4 protocol: %d\n", packetInfo.Protocol);
	}
	else {
		packetInfo.AddressFamily = AF_INET6;
		packetInfo.Port = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
		packetInfo.Protocol = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ipv6 port: %d\n", packetInfo.Port);
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ipv6 protocol: %d\n", packetInfo.Protocol);
	}

	// Get IP and transport header sizes
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE)) {
		headerSize += inMetaValues->transportHeaderSize;
	}
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_IP_HEADER_SIZE)) {
		headerSize += inMetaValues->ipHeaderSize;
	}

	// Capture packet data for each net buffer in the list
	while (netBufferList != NULL) {
		// Retreat the buffer to get the IP header
		// http://msdn.microsoft.com/en-us/library/ff569977.aspx
		if (headerSize) {
			const NDIS_STATUS retreatStatus = NdisRetreatNetBufferDataStart(
				NET_BUFFER_LIST_FIRST_NB(netBufferList),
				headerSize, FALSE, NULL);
			if (retreatStatus != NDIS_STATUS_SUCCESS) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "NdisRetreatNetBufferDataStart failed: %08X\n", retreatStatus);
				continue;
			}
		}

		packetInfo.NetBufferList = netBufferList;
		packetInfo.Inbound = TRUE;

		//CapturePacketData(&packetInfo, Inbound);
		WCP_ShareNetBufferList(&packetInfo);

		// Undo the retreat
		if (headerSize) {
			NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(netBufferList), headerSize, FALSE, NULL);
		}
		netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList);
	}

}



void WCP_OutboundCallout(
	__in const FWPS_INCOMING_VALUES          *inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	__inout_opt void                         *layerData,
	__in_opt const void                      *classifyContext,
	__in const FWPS_FILTER                   *filter,
	__in UINT64                               flowContext,
	__out FWPS_CLASSIFY_OUT                  *classifyOut
) {

	if (!captureRunning) {
		return;
	}

	NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)layerData;
	PACKET_INFO      packetInfo = { 0 };

	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);

	// Permit the packet to continue
	if (classifyOut && (classifyOut->rights == FWPS_RIGHT_ACTION_WRITE) &&
		(classifyOut->actionType != FWP_ACTION_BLOCK)) {
		classifyOut->actionType = FWP_ACTION_CONTINUE;
	}


	if (!netBufferList) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "received empty outbound layerData\n");
		return;
	}

	// Get the connection ID, address family, port, and protocol
	packetInfo.ConnectionId = FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE) ?
		inMetaValues->transportEndpointHandle & UINT32_MAX : UINT32_MAX;
	if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4) {
		packetInfo.AddressFamily = AF_INET;
		packetInfo.Port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
		packetInfo.Protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
	}
	else {
		packetInfo.AddressFamily = AF_INET6;
		packetInfo.Port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
		packetInfo.Protocol = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
	}
	
	// Get the IP addresses (IPv6 address are already in network byte order)
	if (packetInfo.AddressFamily == AF_INET) {
		packetInfo.SrcIp.AsUInt32 = RtlUlongByteSwap(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32);
		packetInfo.DstIp.AsUInt32 = RtlUlongByteSwap(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
	}
	else {

		// FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS returns the pointer value 0x01. only occurs when using IPPACKET instead of TRANSPORT
		RtlCopyMemory(packetInfo.SrcIp.AsUInt8, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16, 16);
		RtlCopyMemory(packetInfo.DstIp.AsUInt8, inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
	}

	
	// Get the existing IP header size, if any
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,
		FWPS_METADATA_FIELD_IP_HEADER_SIZE)) {
		packetInfo.HaveIpHeader = inMetaValues->ipHeaderSize ? TRUE : FALSE;
	}

	// Capture packet data for each net buffer in the list
	while (netBufferList != NULL) {
		packetInfo.NetBufferList = netBufferList;
		packetInfo.Inbound = FALSE;
		WCP_ShareNetBufferList(&packetInfo);
		netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList);
	}
	

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


	NTSTATUS status = STATUS_SUCCESS;

	FWPS_CALLOUT sCallout = { 0 };
	FWPM_CALLOUT mCallout = { 0 };

	FWPM_DISPLAY_DATA displayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;
	if (layerKey == &FWPM_LAYER_INBOUND_TRANSPORT_V4 ||
		layerKey == &FWPM_LAYER_INBOUND_TRANSPORT_V6) {
		sCallout.classifyFn = WCP_InboundCallout;
	}
	else {
		sCallout.classifyFn = WCP_OutboundCallout;
	}
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
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmTransactionBegin failed\n");
		goto Exit;
	}
	inTransaction = TRUE;

	
	RtlZeroMemory(&NPFSubLayer, sizeof(FWPM_SUBLAYER));
	NPFSubLayer.subLayerKey = WCP_SUBLAYER;
	NPFSubLayer.displayData.name = L"WinCap Sub-Layer";
	NPFSubLayer.displayData.description = L"Sub-Layer for use by WinCap callouts";
	NPFSubLayer.flags = 0;
	NPFSubLayer.weight = 0; 

	status = FwpmSubLayerAdd(gWdmDevice, &NPFSubLayer, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "FwpmSubLayerAdd failed\n");
		goto Exit;
	}
	
	
	status = WCP_RegisterCallout(
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		&WCP_OUTBOUND_IPPACKET_CALLOUT_V4,
		deviceObject,
		&g_OutboundIPPacketV4
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV4_1 failed with status: 0x%0x\n", status);
		goto Exit;
	}

	status = WCP_RegisterCallout(
		&FWPM_LAYER_INBOUND_TRANSPORT_V4,
		&WCP_INBOUND_IPPACKET_CALLOUT_V4,
		deviceObject,
		&g_InboundIPPacketV4
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV4_2 with status: 0x%0x\n", status);
		goto Exit;
	}

	status = WCP_RegisterCallout(
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
		&WCP_OUTBOUND_IPPACKET_CALLOUT_V6,
		deviceObject,
		&g_OutboundIPPacketV6
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV6 with status: 0x%0x\n", status);
		goto Exit;
	}

	status = WCP_RegisterCallout(
		&FWPM_LAYER_INBOUND_TRANSPORT_V6,
		&WCP_INBOUND_IPPACKET_CALLOUT_V6,
		deviceObject,
		&g_InboundIPPacketV6
	);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "WCP_RegisterCallout_IPV6 failed with status: 0x%0x\n", status);
		goto Exit;
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