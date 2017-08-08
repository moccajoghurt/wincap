//#include <stdafx.h>
#include <stdio.h>
#include <windows.h>

// Device type
#define SIOCTL_TYPE 40000
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_INVERT_NOTIFICATION CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
 
int __cdecl main(int argc, char* argv[]) {
	HANDLE hDevice;
	PCHAR welcome = "Hello from userland.";
	DWORD dwBytesRead = 0;
	long ReadBuffer[1000] = {0};

	hDevice = CreateFile("\\\\.\\WinCap", GENERIC_WRITE|GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error opening Driver (%d)\n", GetLastError());
		system("pause");
        return;
    } else {
		printf("Handle : %p\n",hDevice);
	}
	
	while (1) {
		printf("sending an IOCTL\n");
		//DeviceIoControl(hDevice, IOCTL_HELLO, welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		DeviceIoControl(hDevice, IOCTL_INVERT_NOTIFICATION, NULL, 0, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		printf("DeviceIoControl produced error code (%d)\n", GetLastError());
		printf("Message received from kerneland : %ld\n",*ReadBuffer);
		printf("Bytes read : %d\n", dwBytesRead);
	}
	

	CloseHandle(hDevice);
	
	system("pause");

	return 0;
}