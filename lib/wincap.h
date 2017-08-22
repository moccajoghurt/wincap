#include <windows.h>

// Device type
#define SIOCTL_TYPE 40000
// The IOCTL function codes from 0x800 to 0xFFF are not windows internal.
#define IOCTL_INVERT_NOTIFICATION CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_INVERT_NOTIFICATION_BUF_NUM 100
#define PACKET_BYTE_BUFFER_SIZE 2000
#define MAC_HEADER_BYTE_NUM 14
#define PACKET_INFO_SIZE 41

//------------------- Global 
typedef struct _NETWORK_PACKET {
	// ---- packet info
	UCHAR 	isInbound;
	UCHAR 	isIpv4;
	UINT32	sourceIpv4;     // IPv4
	UINT32	targetIpv4;     // IPv4
	UINT8	sourceIpv6[16];  // IPv6
	UINT8	targetIpv6[16];  // IPv6
	UINT16	port;
	UINT8	protocol;
	UINT32	processId;
	DWORD dataSize;
	// ---- packet data
	void* dataBytes;
	
} NETWORK_PACKET, *PNETWORK_PACKET;


BOOL startCapture(VOID (*callbackFunc)(NETWORK_PACKET));
VOID stopCapture(void);
VOID endWincap(void);
VOID printPacketInfo(PNETWORK_PACKET);

//------------------- Internal
static HANDLE hDevice = NULL;
static BOOL driverInitialized = FALSE;
static BOOL captureRunning = FALSE;

static BOOL initDriver(void);
static VOID createIoctlBuf(VOID (*callbackFunc)(NETWORK_PACKET));
static VOID sendIoctlNotification(VOID (*callbackFunc)(NETWORK_PACKET));