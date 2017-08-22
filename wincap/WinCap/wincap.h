

#ifndef _WINCAP_H_
#define _WINCAP_H_


//#pragma warning(push)
//#pragma warning(disable:4201)       // unnamed struct/union

#include <Ndis.h>
#include <fwpsk.h>
#include <wdf.h>

//#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>


//#pragma pack(push)
//#pragma pack (1)


//#pragma pack(pop)

DEFINE_GUID(WCP_OUTBOUND_IPPACKET_CALLOUT_V4, 0x2d605b3e, 0xc244, 0x4364, 0x86, 0xe8, 0xbd, 0x81, 0xe6, 0xc9, 0x1b, 0x6d);
DEFINE_GUID(WCP_OUTBOUND_IPPACKET_CALLOUT_V6, 0xf935e4cd, 0x9499, 0x4934, 0x82, 0x4d, 0x8e, 0x37, 0x26, 0xba, 0x4a, 0x93);
DEFINE_GUID(WCP_INBOUND_IPPACKET_CALLOUT_V4, 0xed7e5eb2, 0x6b09, 0x4783, 0x96, 0x1c, 0x54, 0x95, 0xea, 0xad, 0x36, 0x1e);
DEFINE_GUID(WCP_INBOUND_IPPACKET_CALLOUT_V6, 0x21022f40, 0x9578, 0x4c39, 0x98, 0xa5, 0xc9, 0x7b, 0x8d, 0x83, 0x4e, 0x27);
DEFINE_GUID(WCP_SUBLAYER, 0x2f32c254, 0xa054, 0x469b, 0xb9, 0x9b, 0x3e, 0x88, 0x10, 0x27, 0x5a, 0x71);


#define UINT32_MAX 0xffffffff

typedef union _IP_ADDRESS {
	UINT8   AsUInt8[16];  // IPv6
	UINT32  AsUInt32;     // IPv4
}IP_ADDRESS;

// Information needed to capture packet data
typedef struct _PACKET_INFO {
	ADDRESS_FAMILY   AddressFamily;  // IPv4 or IPv6
	UINT32           ConnectionId;   // 32-bit connection associated with packet
	BOOL             HaveIpHeader;   // True if outbound packet has an IP header
	NET_BUFFER_LIST *NetBufferList;  // Holds packet data
	UINT16           Port;           // Local port associated with packet
	UINT8            Protocol;       // IP protocol for this packet
	IP_ADDRESS       SrcIp;          // Source IP address for outbound packets
	IP_ADDRESS       DstIp;          // Destination IP address for outbound packets
	BOOL			 Inbound;		 // True if packet is inbound
}PACKET_INFO;

void WCP_InboundCallout(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

void WCP_OutboundCallout(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);


NTSTATUS
WCP_NetworkNotify(
	_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	_In_ const GUID* filterKey,
	_Inout_ const FWPS_FILTER* filter
);

NTSTATUS
WCP_AddFilter(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey
);

NTSTATUS
WCP_RegisterCallout(
	_In_ const GUID* layerKey,
	_In_ const GUID* calloutKey,
	_Inout_ void* deviceObject,
	_Out_ UINT32* calloutId
);

NTSTATUS
WCP_RegisterCallouts(
	_Inout_ void* deviceObject
);

void
WCP_UnregisterCallouts();

NTSTATUS
WCP_InitInjectionHandles();

NTSTATUS
WCP_FreeInjectionHandles();

NTSTATUS
WCP_ShareNetBufferList(
	PACKET_INFO* packetInfo
);

//****************** Inverted Call Method related

typedef struct _INVERTED_DEVICE_CONTEXT {
	WDFQUEUE    NotificationQueue;
	LONG		QueueCount;
} INVERTED_DEVICE_CONTEXT, *PINVERTED_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(INVERTED_DEVICE_CONTEXT, InvertedGetContextFromDevice)

NTSTATUS
WCP_DeviceAdd(
	IN WDFDRIVER Driver,
	IN PWDFDEVICE_INIT DeviceInit
);

EVT_WDF_DRIVER_UNLOAD WCP_DriverUnload;
EVT_WDF_DEVICE_SHUTDOWN_NOTIFICATION WCP_Shutdown;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL WCP_IoDeviceControl;
EVT_WDF_IO_IN_CALLER_CONTEXT WCP_DeviceIoInCallerContext;
EVT_WDF_DEVICE_FILE_CREATE WCP_FileCreate;
EVT_WDF_FILE_CLOSE WCP_FileClose;

#endif // _WINCAP_H_