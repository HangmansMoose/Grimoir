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





class WebSocket {
private:
    WSADATA m_wsaData;
    void GetErrorMessage(DWORD dw_error, char** p_msg);
    void tls_connect(tls_socket* socket);
    void tls_disconnect(tls_socket* socket)


public:
    WebSocket() = default;
    ~WebSocket() = default;
    bool Init();
    bool Connect(const char* hostname, uint16_t port);


};
