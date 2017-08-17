#include "wincap.h"
#include <stdio.h>

BOOL startCapture(VOID (*callbackFunc)(NETWORK_PACKET)) {
	if (!driverInitialized) {
		BOOL success = initDriver();
		if (!success) {
			return FALSE;
		}
		else {
			driverInitialized = TRUE;
		}
	}
	DeviceIoControl(hDevice, IOCTL_START_CAPTURE, NULL, 0, NULL, 0, NULL, NULL);
	captureRunning = TRUE;
	createIoctlBuf(callbackFunc);
	return TRUE;
}

VOID stopCapture() {
	captureRunning = FALSE;
}

VOID endWincap() {
	if (hDevice != NULL) {
		CloseHandle(hDevice);
	}
}

/*
VOID debugPrintRawBytes(PNETWORK_PACKET p) {
	
	for (int i = 0; i < p->dataSize; i++) {
		if (*(p->dataBytes + i * sizeof(char)) == 0) {
			printf(".");
		} else {
			printf("%c", *(p->dataBytes + i * sizeof(char)));
		}
	}
	printf("\n");
	printf("Bytes read : %d\n", p->dataSize);
}
*/

VOID printPacketInfo(PNETWORK_PACKET p) {
	if (p->isInbound) {
		
		printf("inbound package\n");
	}
	else {
		printf("outbound package\n");
	}
	if (p->isIpv4 && !p->isInbound) {
		int block;
		printf("Source IP: ");
		printf("%d.", p->sourceIpv4 >> 24);
		block = p->sourceIpv4;
		block <<= 8;
		block >>= 24;
		printf("%d.", block);
		block = p->sourceIpv4;
		block <<= 16;
		block >>= 24;
		printf("%d.", block);
		block = p->sourceIpv4;
		block <<= 24;
		block >>= 24;
		printf("%d\n", block);
		
		printf("Target IP: ");
		printf("%d.", p->targetIpv4 >> 24);
		block = p->targetIpv4;
		block <<= 8;
		block >>= 24;
		printf("%d.", block);
		block = p->targetIpv4;
		block <<= 16;
		block >>= 24;
		printf("%d.", block);
		block = p->targetIpv4;
		block <<= 24;
		block >>= 24;
		printf("%d\n", block);
	}
	else if (!p->isIpv4 && !p->isInbound) {
		printf("Source IP: ");
		for (int i = 0; i < 16; i++) {
			printf("%hhX", p->sourceIpv6[i]);
			if ((i+1)%2 == 0 && i != 15) {
				printf(".");
			}
		}
		printf("\n");
		
		printf("Target IP: ");
		for (int i = 0; i < 16; i++) {
			printf("%hhX", p->targetIpv6[i]);
			if ((i+1)%2 == 0 && i != 15) {
				printf(".");
			}
		}
		printf("\n");
	}
	else {
		printf("Source IP: localhost\n");
		printf("Target IP: localhost\n");
	}
	printf("port: %d\n", p->port);
	printf("protocol: %d\n", p->protocol);
	printf("process id: %d\n", p->processId);
	printf("data size: %d\n", p->dataSize);
	printf("#########\n");
}

// ------------------------------- INTERNAL

BOOL initDriver(void) {
	hDevice = CreateFile("\\\\.\\WinCap", GENERIC_WRITE|GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Error opening Driver. CreateFile returned error code (%d)\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

VOID createIoctlBuf(VOID (*callbackFunc)(NETWORK_PACKET)) {
	for (int i = 0; i < IOCTL_INVERT_NOTIFICATION_BUF_NUM; i++) {
		_beginthread(sendIoctlNotification, 0, callbackFunc);
	}
}

VOID sendIoctlNotification(VOID (*callbackFunc)(NETWORK_PACKET)) {
	DWORD dwBytesRead = 0;
	size_t byteCount = PACKET_BYTE_BUFFER_SIZE;
	void* packetBuffer = calloc(byteCount, 1);
	DeviceIoControl(hDevice, IOCTL_INVERT_NOTIFICATION, NULL, 0, packetBuffer, byteCount, &dwBytesRead, NULL);
	//we received a package
	// if the capture is running, send a new IOCTL request
	if (captureRunning) {
		_beginthread(sendIoctlNotification, 0, callbackFunc);
	}
	NETWORK_PACKET p;
	BOOL success = createNetworkPacket(&p, packetBuffer, dwBytesRead);
	if (!success) {
		printf("received empty package. IOCTL buffer might be too small\n");
		return;
	}
	callbackFunc(p);
}

BOOL createNetworkPacket(PNETWORK_PACKET p, void* packetBuffer, DWORD dwBytesRead) {
	
	if (dwBytesRead == 0) {
		return FALSE;
	}
	
	UINT32 ptrOffset = 0;
	BOOL* bPtr;
	UINT8* uint8Ptr;
	UINT16* uint16Ptr;
	UINT32* uint32Ptr;
	
	bPtr = (BOOL*)((BYTE*)packetBuffer + ptrOffset);
	p->isInbound = *bPtr;
	ptrOffset += 1;
	
	bPtr = (BOOL*)((BYTE*)packetBuffer + ptrOffset);
	p->isIpv4 = *bPtr;
	ptrOffset += 1;
	
	if (p->isIpv4) {
		uint32Ptr = (UINT32*)((BYTE*)packetBuffer + ptrOffset);
		p->sourceIpv4 = *uint32Ptr;
		ptrOffset += 16;
		
		uint32Ptr = (UINT32*)((BYTE*)packetBuffer + ptrOffset);
		p->targetIpv4 = *uint32Ptr;
		ptrOffset += 16;
	}
	else {
		uint8Ptr = (UINT8*)((BYTE*)packetBuffer + ptrOffset);
		memcpy(p->sourceIpv6, uint8Ptr, sizeof(UINT8)*16);
		ptrOffset += 16;
		
		uint8Ptr = (UINT8*)((BYTE*)packetBuffer + ptrOffset);
		memcpy(p->targetIpv6, uint8Ptr, sizeof(UINT8)*16);
		ptrOffset += 16;
	}
	
	uint16Ptr = (UINT16*)((BYTE*)packetBuffer + ptrOffset);
	p->port = *uint16Ptr;
	ptrOffset += 2;
	
	uint8Ptr = (UINT8*)((BYTE*)packetBuffer + ptrOffset);
	p->protocol = *uint8Ptr;
	ptrOffset += 1;
	
	uint32Ptr = (UINT32*)((BYTE*)packetBuffer + ptrOffset);
	p->processId = *uint32Ptr;
	ptrOffset += 4;
	
	p->dataSize = dwBytesRead - PACKET_INFO_SIZE;
	p->dataBytes = calloc(p->dataSize, sizeof(BYTE));
	memcpy(p->dataBytes, (BYTE*)packetBuffer + ptrOffset, p->dataSize);
	
	return TRUE;
}
