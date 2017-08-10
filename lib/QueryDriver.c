//#include <stdafx.h>
#include <stdio.h>
#include <windows.h>

// Device type
#define SIOCTL_TYPE 40000
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_INVERT_NOTIFICATION CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_CAPTURE CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
 
int __cdecl main(int argc, char* argv[]) {
	HANDLE hDevice;
	PCHAR welcome = "Hello from userland.";
	DWORD dwBytesRead = 0;
	size_t byteCount = 1000;
	char* ReadBuffer = calloc(byteCount, sizeof(char));

	hDevice = CreateFile("\\\\.\\WinCap", GENERIC_WRITE|GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Error opening Driver (%d)\n", GetLastError());
		system("pause");
		return;
	} else {
		printf("Handle : %p\n",hDevice);
	}
	
	DeviceIoControl(hDevice, IOCTL_START_CAPTURE, NULL, 0, NULL, 0, NULL, NULL);
	while (1) {
		DeviceIoControl(hDevice, IOCTL_INVERT_NOTIFICATION, NULL, 0, ReadBuffer, byteCount, &dwBytesRead, NULL);
		for (int i = 0; i < dwBytesRead; i++) {
			if (*(ReadBuffer + i * sizeof(char)) == 0) {
				printf(".");
			} else {
				printf("%c", *(ReadBuffer + i * sizeof(char)));
			}
		}
		printf("\n");
		printf("Bytes read : %d\n", dwBytesRead);
	}
	
	DeviceIoControl(hDevice, IOCTL_STOP_CAPTURE, NULL, 0, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	
	CloseHandle(hDevice);
	
	system("pause");

	return 0;
}