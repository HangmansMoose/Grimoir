#include "WebSocket.h"
#include <Shlwapi.h>
#include <winsock2.h>

bool WebSocket::Init(){
    // Initialise Windows Sockets
    if(WSAStartup(MAKEWORD(2, 2), &m_wsaData) != 0) {
        fprintf(stderr, "Could not init WSA\n");        
        return false;
    }

    return true;

}

bool WebSocket::Connect(const char* hostname, uint16_t port) {

    m_webSocket.socket = socket(AF_INET, SOCK_STREAM, 0);
    if(m_webSocket.socket == INVALID_SOCKET) {
        WSACleanup();
        fprintf(stderr, "Could not obtain a valid socket\n");
        return false;
    }

	char portAsString[64];
	wnsprintfA(portAsString, sizeof(portAsString), "%u", port);

// FWD declare for clang lsp, not needed for compilation
/*
BOOL WSAConnectByNameW(
  [in]      SOCKET          s,
  [in]      LPCSTR          nodename,
  [in]      LPCSTR          servicename,
  [in, out] LPDWORD         LocalAddressLength,
  [out]     LPSOCKADDR      LocalAddress,
  [in, out] LPDWORD         RemoteAddressLength,
  [out]     LPSOCKADDR      RemoteAddress,
  [in]      const timeval   *timeout,
);	
*/

	if (!WSAConnectByNameW(m_webSocket.socket, hostname, portAsString, NULL, NULL, NULL, NULL, NULL))
	{
		closesocket(m_webSocket.socket);
		WSACleanup();
		return false;
	}

	// SChannel init
	SCHANNEL_CRED tlsCred = {};

	tlsCred.dwVersion = SCHANNEL_CRED_VERSION;
	tlsCred.dwFlags = SCH_USE_STRONG_CRYPTO
					| SCH_CRED_AUTO_CRED_VALIDATION
					| SCH_CRED_NO_DEFAULT_CREDS;
	tlsCred.grbitEnabledProtocols = SP_PROT_TLS1_3 | SP_PROT_TLS1_2;
	
    return true;
}

// Passes the received error code and an empty buffer to FormatMessage which will fill out the buffer
// with the error message
void WebSocket::GetErrorMessage(DWORD errorType, char** p_msg) {

    DWORD errorFlags;

    errorFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER
               | FORMAT_MESSAGE_FROM_SYSTEM
               | FORMAT_MESSAGE_IGNORE_INSERTS;
    
    FormatMessage(errorFlags, NULL, errorType, LANG_SYSTEM_DEFAULT, (LPTSTR)p_msg, 0, NULL);
}


