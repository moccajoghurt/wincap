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

VOID printNetworkPacket(PNETWORK_PACKET p) {
	
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
	char* packetBuffer = calloc(byteCount, sizeof(char));
	DeviceIoControl(hDevice, IOCTL_INVERT_NOTIFICATION, NULL, 0, packetBuffer, byteCount, &dwBytesRead, NULL);
	//we received a package
	NETWORK_PACKET p;
	p.dataBytes = packetBuffer;
	p.dataSize = dwBytesRead;
	
	// if the capture is running, send a new IOCTL request
	if (captureRunning) {
		_beginthread(sendIoctlNotification, 0, callbackFunc);
	}
	callbackFunc(p);
}

