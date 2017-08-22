

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

// Uuidgen.exe
DEFINE_GUID(WCP_OUTBOUND_TRANSPORT_CALLOUT_V4, 0x78516b9b, 0x4387, 0x4f67, 0x9a, 0xcf, 0xb8, 0x57, 0x88, 0x5d, 0xf4, 0xbe);
DEFINE_GUID(WCP_OUTBOUND_TRANSPORT_CALLOUT_V6, 0x78692dfc, 0x1c62, 0x4adf, 0x94, 0x6f, 0xaa, 0xcd, 0xef, 0xe4, 0x33, 0x91);
DEFINE_GUID(WCP_INBOUND_TRANSPORT_CALLOUT_V4, 0x0eade3ff, 0x15a5, 0x46fd, 0x83, 0xd0, 0x5d, 0x81, 0x14, 0x5c, 0xd6, 0x04);
DEFINE_GUID(WCP_INBOUND_TRANSPORT_CALLOUT_V6, 0x3a936b2f, 0x7d24, 0x42ea, 0xa3, 0x40, 0x2a, 0xf0, 0x80, 0xb0, 0xec, 0x6e);
DEFINE_GUID(WCP_SUBLAYER, 0x727abf37, 0xa1af, 0x417c, 0xa4, 0x99, 0xc0, 0xd1, 0xe6, 0xa7, 0xab, 0x58);

//for process ID grabbing
DEFINE_GUID(WCP_AUTH_CONNECT_CALLOUT_V4, 0x5d6870c7, 0xa2ca, 0x42d5, 0xb8, 0xa3, 0x3d, 0x76, 0x2b, 0x94, 0x3b, 0xe2);
DEFINE_GUID(WCP_AUTH_CONNECT_CALLOUT_V6, 0x5924b468, 0xc9de, 0x49df, 0x93, 0xbc, 0xff, 0x60, 0x18, 0x59, 0x45, 0x68);
DEFINE_GUID(WCP_RECV_ACCEPT_CALLOUT_V4, 0x10f10ebe, 0x8b11, 0x4922, 0x85, 0xa8, 0x75, 0xb4, 0xbd, 0xe2, 0x7d, 0x01);
DEFINE_GUID(WCP_RECV_ACCEPT_CALLOUT_V6, 0x965a6da8, 0x05c6, 0x44ef, 0xbe, 0xe6, 0x80, 0x66, 0x4f, 0x34, 0xe3, 0xe9);
DEFINE_GUID(WCP_RESOURCE_ASSIGNMENT_CALLOUT_V4, 0x26cc16ce, 0x2eaf, 0x4f14, 0x81, 0x11, 0xdd, 0x7e, 0x5f, 0x1a, 0x1c, 0xa6);
DEFINE_GUID(WCP_RESOURCE_ASSIGNMENT_CALLOUT_V6, 0xef08dce7, 0x618c, 0x4e2a, 0x88, 0x53, 0x44, 0xeb, 0x62, 0x33, 0x15, 0x3e);
DEFINE_GUID(WCP_ENDPOINT_CLOSURE_CALLOUT_V4, 0x455c4768, 0xec8c, 0x46a3, 0xaa, 0x98, 0xe1, 0xfa, 0xe0, 0xd8, 0xdf, 0x43);
DEFINE_GUID(WCP_ENDPOINT_CLOSURE_CALLOUT_V6, 0xe8aab6ca, 0x3401, 0x420a, 0xa2, 0x34, 0x99, 0x73, 0xd7, 0x43, 0x53, 0x7a);
DEFINE_GUID(WCP_RESOURCE_RELEASE_CALLOUT_V4, 0xfdb318fe, 0x3c90, 0x4d65, 0x93, 0xcb, 0xac, 0x96, 0x0c, 0xe6, 0x3d, 0x86);
DEFINE_GUID(WCP_RESOURCE_RELEASE_CALLOUT_V6, 0x25e0dc93, 0x8d33, 0x41ad, 0x94, 0xa8, 0xe0, 0xbc, 0x1b, 0xeb, 0x06, 0xd0);


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


typedef struct _PROCESS_ID {
	UINT32 ConnectionId;
	UINT32 ProcessId;
	SINGLE_LIST_ENTRY SingleListEntry;

}PROCESS_LIST_VALUE, *PPROCESS_LIST_VALUE;

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

void WCP_ConnectionCallout(
	__in const FWPS_INCOMING_VALUES          *inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES *inMetaValues,
	__inout_opt void                         *layerData,
	__in_opt const void                      *classifyContext,
	__in const FWPS_FILTER                   *filter,
	__in UINT64                               flowContext,
	__out FWPS_CLASSIFY_OUT                  *classifyOut
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