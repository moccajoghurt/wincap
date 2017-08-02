//#include <stdafx.h>
#include <stdio.h>
#include <windows.h>

// Device type
#define SIOCTL_TYPE 40000
 
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
#define IOCTL_HELLO CTL_CODE( SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
 
 void printDosDevices();
 
int __cdecl main(int argc, char* argv[])
{
	HANDLE hDevice;
	PCHAR welcome = "Hello from userland.";
	DWORD dwBytesRead = 0;
	char ReadBuffer[50] = {0};
	
	// printDosDevices();

	hDevice = CreateFile("\\\\.\\WinCap", GENERIC_WRITE|GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	// hDevice = CreateFile(L"\\\\.\\ROOT\\SAMPLE\\WinCap", GENERIC_WRITE|GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Error opening Driver (%d)\n", GetLastError());
		system("pause");
        return;
    } else {
		printf("Handle : %p\n",hDevice);
	}
	

	DeviceIoControl(hDevice, IOCTL_HELLO, welcome, strlen(welcome), ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	printf("Message received from kerneland : %s\n",ReadBuffer);
	printf("Bytes read : %d\n", dwBytesRead);

	CloseHandle(hDevice);
	
	system("pause");

	return 0;
}


void printDosDevices() {
	TCHAR lpTargetPath[1000];
	DWORD test;
	test = QueryDosDevice(NULL, (LPWSTR)lpTargetPath, 1000);
	printf("The DOS devices are: %s: ", lpTargetPath);
}