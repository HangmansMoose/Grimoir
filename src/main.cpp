#include <stdio.h>
#include "WebSocket.h"
/*
	- Websockets 
		- Create Socket                      /
		- Connect on socket using TLS        / This all needs to be async/multithreaded in the end as well
		- Maintain connection				 /
	- Commands 
		- Processlist
		- Netstat
		- logged in users 
	- Parsing
		- Parse receieved packets from serialized form to readable form
		- Serialize packets to be sent 
	- Logging
		- Need to implement my own logging class. Might be best to do this first as it will greatly assist debugging!

*/

int main(int argc, char* argv[]) {
	printf("Hello, sailor\n");
	return 0;
}