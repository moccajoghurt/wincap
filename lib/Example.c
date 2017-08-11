
#include "wincap.h"

// will be called whenever a network package is sent or received
void myCallback(NETWORK_PACKET p) {
	printNetworkPacket(&p);
}

int main(int argc, char* argv[]) {
	
	printf("Starting WinCap\n");
	startCapture(myCallback);
	while(TRUE) {Sleep(2000);}
	
	stopCapture();
	endWincap();

	return 0;
}