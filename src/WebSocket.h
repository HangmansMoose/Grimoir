#pragma once
#ifndef UNICODE
#define UNICODE
#endif

// WIN32_LEAN_AND_MEAN ensures that winsock.h is not included from windows.h
// It does not play well with winsock2.h
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winternl.h> // without this NTSTATUS was undefined

// If the security api is to be used you must define either SECURITY_WIN32, SECURITY_KERNEL, or SECURITY_MAC
// SECURITY_WIN32 - for accessing the security api from user mode
// SECURITY_KERNEL - for accessing the security api from kernel mode
// SECURITY_MAC - Legacy MFC compatibility 

#define SECURITY_KERNEL
#include <security.h>
#include <schannel.h>
#include <stdio.h>
#include <inttypes.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")


#define TLS_MAX_PACKET_SIZE 65536

enum TLS_State
{
	TLS_STATE_BAD_CERTIFICATE                       = -8, // Bad or unsupported cert format.
	TLS_STATE_SERVER_ASKED_FOR_CLIENT_CERTS         = -7, // Not supported.
	TLS_STATE_CERTIFICATE_EXPIRED                   = -6,
	TLS_STATE_BAD_HOSTNAME                          = -5,
	TLS_STATE_CANNOT_VERIFY_CA_CHAIN                = -4,
	TLS_STATE_NO_MATCHING_ENCRYPTION_ALGORITHMS     = -3,
	TLS_STATE_INVALID_SOCKET                        = -2,
	TLS_STATE_UNKNOWN_ERROR                         = -1,
	TLS_STATE_DISCONNECTED                          = 0,
	TLS_STATE_DISCONNECTED_BUT_PACKETS_STILL_REMAIN = 1,  // The TCP socket closed, but you should keep calling `tls_read`.
	TLS_STATE_PENDING                               = 2,  // Handshake in progress.
	TLS_STATE_CONNECTED                             = 3,
	TLS_STATE_PACKET_QUEUE_FILLED                   = 4,  // Not calling `tls_read` enough. Did you forget to call this in a loop after `tls_process`?
};

typedef struct tls_Socket{
    SOCKET socket;
    CredHandle handle;
    CtxtHandle context;
    SecPkgContext_StreamSizes sizes;
    int received;   // Byte count on incoming buffer
    int used;       // Byte count used from incoming buffer to decrypt current packet
    int available;  // Byte count available for decrypted bytes
    char* decrypted; // points to incoming buffer where data is decrypted in place 
    char incoming[TLS_MAX_PACKET_SIZE];
}tls_Socket;



class WebSocket {
private:
    WSADATA m_wsaData;
    tls_Socket m_webSocket;
    void GetErrorMessage(DWORD dw_error, char** p_msg);

public:
    WebSocket() = default;
    ~WebSocket() = default;
    bool Init();
    bool Connect(const char* hostname, uint16_t port);


};
