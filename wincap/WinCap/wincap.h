

#ifndef _INSPECT_H_
#define _INSPECT_H_


#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <Ndis.h>
#include <fwpsk.h>

#pragma warning(pop)

#include <fwpmk.h>

#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>

#define INITGUID
#include <guiddef.h>

#define IPPROTO_NPCAP_LOOPBACK		250

//
// Protocol headers
//

#pragma pack(push)
#pragma pack (1)

//#include "macros.h"

/*
* Structure of a IPv4 header, based on netinet/ip.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP_HEADER {
	UCHAR     ip_hVerLen;			/* Version (4 bits) + Internet header length (4 bits) */
	UCHAR     ip_TOS;				/* TOS Type of service */
	USHORT    ip_Length;			/* Total length */
	USHORT    ip_ID;				/* Identification */
	USHORT    ip_Flags;				/* Flags (3 bits) + Fragment offset (13 bits) */
	UCHAR     ip_TTL;				/* Time to live */
	UCHAR     ip_Protocol;			/* Protocol */
	USHORT    ip_Checksum;			/* Header checksum */
	ULONG     ip_Src;				/* Source address */
	ULONG     ip_Dst;				/* Destination address */
} IP_HEADER, *PIP_HEADER;

/*
* The length of the IPv4 header.
*/
#define	IP_HDR_LEN		sizeof(IP_HEADER)

/*
* Structure of a IPv6 header, based on netinet/ip6.h
* http://openhip.sourceforge.net/doxygen/ip_8h_source.html
*/
typedef struct _IP6_HEADER {
	union {
		struct _ip6_HeaderCtl {
			ULONG ip6_VerFlow;		/* 4 bits version, 8 bits TC, 20 bits flow-ID */
			USHORT ip6_PLength;		/* Payload length */
			UCHAR ip6_NextHeader;	/* Next header */
			UCHAR ip6_HopLimit;		/* Hop limit */
		} ip6_HeaderCtl;
		UCHAR ip6_VFC;				/* 4 bits version, top 4 bits tclass */
	} ip6_CTL;
	struct in6_addr ip6_Src;		/* Source address */
	struct in6_addr ip6_Dst;		/* Destination address */
} IP6_HEADER, *PIP6_HEADER;

/*
* The length of the IPv6 header.
*/
#define	IPV6_HDR_LEN		sizeof(IP6_HEADER)

/*
* Structure of a ICMP header
* https://www.cymru.com/Documents/ip_icmp.h
*/
typedef struct _ICMP4_HEADER {
	UCHAR icmp_Type;				/* Message type */
	UCHAR icmp_Code;				/* Type sub-code */
	USHORT icmp_Checksum;
	union {
		struct _icmp_Echo {
			USHORT	icmp_Id;
			USHORT	icmp_Sequence;
		} icmp_Echo;				/* Echo datagram */
		ULONG	icmp_Gateway;		/* Gateway address */
		struct _icmp_Frag {
			USHORT	icmp_Unused;
			USHORT	icmp_Mtu;
		} icmp_Frag;				/* Path MTU discovery */
	} icmp_Un;
} ICMP4_HEADER, *PICMP4_HEADER;

#define ICMP_TYPE_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_CODE_PROT_UNREACH	2	/* Protocol Unreachable		*/

/*
* The length of the IPv6 header.
*/
#define	ICMP_HDR_LEN		sizeof(ICMP4_HEADER)

#pragma pack(pop)

//
// Shared function prototypes
//

#if(NTDDI_VERSION >= NTDDI_WIN7)

void WCP_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_opt_ const void* classifyContext,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

#else /// (NTDDI_VERSION >= NTDDI_WIN7)

void
WCP_NetworkClassify(
	_In_ const FWPS_INCOMING_VALUES* inFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	_Inout_opt_ void* layerData,
	_In_ const FWPS_FILTER* filter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* classifyOut
);

#endif /// (NTDDI_VERSION >= NTDDI_WIN7)

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
WCP_UnregisterCallouts(
);

NTSTATUS
WCP_InitInjectionHandles(
);

NTSTATUS
WCP_FreeInjectionHandles(
);

NTSTATUS
WCP_ShareClonedNetBufferList(
	PNET_BUFFER_LIST clonedNetBufferList,
	BOOLEAN bSelfSent
);

#endif // _INSPECT_H_