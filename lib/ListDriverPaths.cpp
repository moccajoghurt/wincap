#include <iostream>
#include <vector>
#include <windows.h>
#include <Setupapi.h> //HDEVINFO

using namespace std;

int main() {
	GUID DeviceInterface;
	HDEVINFO hDevInfo = SetupDiCreateDeviceInfoList(NULL, NULL);
	if(hDevInfo == INVALID_HANDLE_VALUE) {
		cout << "invalid handle value" << endl;
	    return 1;
	}

	std::vector<SP_INTERFACE_DEVICE_DATA> interfaces;

	for (DWORD i = 0; true; ++i) {
		cout << "retrieving device: "  << i << endl;
	    SP_DEVINFO_DATA devInfo;
	    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
	    BOOL status = SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo);
		if (!status) {
			cout << "SetupDiEnumDeviceInfo wasn't successful error code: " << GetLastError() << endl;
			break;
		}

	    SP_INTERFACE_DEVICE_DATA ifInfo;
	    ifInfo.cbSize = sizeof(SP_INTERFACE_DEVICE_DATA);
	    if (TRUE != SetupDiEnumDeviceInterfaces(hDevInfo, &devInfo,  &(DeviceInterface), 0, &ifInfo)) {
	        if (GetLastError() != ERROR_NO_MORE_ITEMS) {
				cout << "SetupDiEnumDeviceInterfaces: ERROR_NO_MORE_ITEMS" << endl;
	            break;
			}
	    }
	    interfaces.push_back(ifInfo);
	}

	std::vector<SP_INTERFACE_DEVICE_DETAIL_DATA*> devicePaths;
	for (size_t i = 0; i < interfaces.size(); ++i) {
	    DWORD requiredSize = 0;
	    SetupDiGetDeviceInterfaceDetail(hDevInfo, &(interfaces.at(i)), NULL, NULL, &requiredSize, NULL);
	    SP_INTERFACE_DEVICE_DETAIL_DATA* data = (SP_INTERFACE_DEVICE_DETAIL_DATA*) malloc(requiredSize);
	    data->cbSize = sizeof(SP_INTERFACE_DEVICE_DETAIL_DATA);

	    if (!SetupDiGetDeviceInterfaceDetail(hDevInfo, &(interfaces.at(i)), data, requiredSize, NULL, NULL)) {
	        continue;
	    }
		cout << data << endl;
	    devicePaths.push_back(data);
	}
	system("pause");
}