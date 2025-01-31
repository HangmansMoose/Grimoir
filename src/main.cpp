#include "WebSocket.h"
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")

int main()
{
    const char* hostname = "www.google.com";
    //const char* hostname = "badssl.com";
    //const char* hostname = "expired.badssl.com";
    //const char* hostname = "wrong.host.badssl.com";
    //const char* hostname = "self-signed.badssl.com";
    //const char* hostname = "untrusted-root.badssl.com";
    const char* path = "/";
	
	WebSocket* ws = new WebSocket;

    ws->Init();
	

    tls_socket s;
    if (ws->tls_connect(&s, hostname, 443) != 0)
    {
        printf("Error connecting to %s\n", hostname);
        return -1;
    }
 
    printf("Connected!\n");
 
    // send request
    char req[1024];
    int len = sprintf(req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname);
    if (ws->tls_write(&s, req, len) != 0)
    {
        ws->tls_disconnect(&s);
        delete ws;
        return -1;
    }
 
    // write response to file
    FILE* f = fopen("response.txt", "wb");
    int received = 0;
    for (;;)
    {
        char buf[65536];
        int r = ws->tls_read(&s, buf, sizeof(buf));
        if (r < 0)
        {
            printf("Error receiving data\n");
            break;
        }
        else if (r == 0)
        {
            printf("Socket disconnected\n");
            break;
        }
        else
        {
            fwrite(buf, 1, r, f);
            fflush(f);
            received += r;
        }
    }
    fclose(f);
 
    printf("Received %d bytes\n", received);

   ws->tls_disconnect(&s);
    
}

