#include <memory>
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winsock2.h>
#include <WS2tcpip.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>
#include <thread>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

#define TLS_MAX_PACKET_SIZE (16384+512) // payload + extra over head for header/mac/padding (probably an oveservInfotimate)


char* nc_error;
DWORD dw_error;
int   i_status;

typedef struct {
	SOCKET sock;
	CredHandle handle;
	CtxtHandle context;
	SecPkgContext_StreamSizes sizes;
	int received;    // byte count in incoming buffer (ciphertext)
	int used;        // byte count used from incoming buffer to decrypt current packet
	int available;   // byte count available for decrypted bytes
	char* decrypted; // points to incoming buffer where data is decrypted inplace
	char incoming[TLS_MAX_PACKET_SIZE];
} tls_socket;

void get_msg_text
(
	DWORD  dw_error, 
	char** pnc_msg    
)
{
	DWORD dw_flags;
	/*                                                                            */
	/* Set message options:                                                       */
	/*                                                                            */
	dw_flags = FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_IGNORE_INSERTS;
	/*                                                                            */
	/* Create the message string:                                                 */
	/*                                                                            */
	FormatMessage(dw_flags, NULL, dw_error, LANG_SYSTEM_DEFAULT, (LPTSTR)pnc_msg, 0,
		NULL);
}

// returns 0 on success or negative value on error
static int tls_connect(tls_socket* currentSocket, const char* hostname, unsigned short port)
{
	// initialize windows sockets
	WSADATA wsadata;
	addrinfo hints = {};
	addrinfo *servInfo = {};
	i_status = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (i_status != 0)
	{

		dw_error = (DWORD)i_status;
		get_msg_text(dw_error, &nc_error);
		fprintf(stderr, "WSAStartup failed with code %d.\n", i_status);
		fprintf(stderr, "%s\n", nc_error);
		LocalFree(nc_error);
		return -1;
	}
	
	char sport[64];
	wnsprintfA(sport, sizeof(sport), "%u", port);
	
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	
	i_status = getaddrinfo(hostname, sport, &hints, &servInfo);
	if (i_status != 0)
	{
		dw_error = (DWORD)i_status;
		get_msg_text(dw_error, &nc_error);
		fprintf(stderr, "GetaddrInfo failed with code %d.\n", i_status);
		fprintf(stderr, "%s\n", nc_error);
		LocalFree(nc_error);
		freeaddrinfo(servInfo);
		WSACleanup();
		return -1;

	}
	// create TCP IPv4 socket
	currentSocket->sock = socket(servInfo->ai_family, servInfo->ai_socktype, servInfo->ai_protocol);
	if (currentSocket->sock == INVALID_SOCKET)
	{
		dw_error = (DWORD)WSAGetLastError();
		get_msg_text(dw_error, &nc_error);
		fprintf(stderr, "socket failed with code %ld.\n", dw_error);
		fprintf(stderr, "%s\n", nc_error);
		LocalFree(nc_error);
		WSACleanup();
		return -1;
	}


	// connect to server
	if (!WSAConnectByNameA(currentSocket->sock, hostname, sport, NULL, NULL, NULL, NULL, NULL, NULL))
	{
		dw_error = (DWORD)WSAGetLastError();
		get_msg_text(dw_error, &nc_error);
		fprintf(stderr, "Connection failed with code %ld.\n", dw_error);
		fprintf(stderr, "%s\n", nc_error);
		LocalFree(nc_error);
		closesocket(currentSocket->sock);
		WSACleanup();
		return -1;
	}

	// initialize schannel

	SCHANNEL_CRED cred = { 0 };

	cred.dwVersion = SCHANNEL_CRED_VERSION;
	cred.dwFlags = SCH_USE_STRONG_CRYPTO          // use only strong crypto alogorithms
		| SCH_CRED_MANUAL_CRED_VALIDATION  // automatically validate server certificate
		| SCH_CRED_NO_DEFAULT_CREDS;     // no client certificate authentication
	cred.grbitEnabledProtocols = SP_PROT_TLS1_2;  // allow only TLS v1.2


	if (AcquireCredentialsHandleW(NULL, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &currentSocket->handle, NULL) != SEC_E_OK)
	{
		dw_error = (DWORD)WSAGetLastError();
		get_msg_text(dw_error, &nc_error);
		fprintf(stderr, "Credential handle failed with code %ld.\n", dw_error);
		fprintf(stderr, "%s\n", nc_error);
		closesocket(currentSocket->sock);
		WSACleanup();
		return -1;
	}


	currentSocket->received = currentSocket->used = currentSocket->available = 0;
	currentSocket->decrypted = NULL;

	// perform tls handshake
	// 1) call InitializeSecurityContext to create/update schannel context
	// 2) when it returns SEC_E_OK - tls handshake completed
	// 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
	// 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
	// 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
	// 6) otherwise read data from server and go to step 1

	CtxtHandle* context = NULL;
	int servInfoult = 0;
	for (;;)
	{
		SecBuffer inbuffers[2] = { 0 };
		inbuffers[0].BufferType = SECBUFFER_TOKEN;
		inbuffers[0].pvBuffer = currentSocket->incoming;
		inbuffers[0].cbBuffer = currentSocket->received;
		inbuffers[1].BufferType = SECBUFFER_EMPTY;

		SecBuffer outbuffers[1] = { 0 };
		outbuffers[0].BufferType = SECBUFFER_TOKEN;

		SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
		SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

		DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
		SECURITY_STATUS sec = InitializeSecurityContextA(
			&currentSocket->handle,
			context,
			context ? NULL : (SEC_CHAR*)hostname,
			flags,
			0,
			0,
			context ? &indesc : NULL,
			0,
			context ? NULL : &currentSocket->context,
			&outdesc,
			&flags,
			NULL);

		// after first call to InitializeSecurityContext context is available and should be reused for next calls
		context = &currentSocket->context;

		if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(currentSocket->incoming, currentSocket->incoming + (currentSocket->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
			currentSocket->received = inbuffers[1].cbBuffer;
		}
		else
		{
			currentSocket->received = 0;
		}

		if (sec == SEC_E_OK)
		{
			// tls handshake completed
			break;
		}
		else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			// server asked for client certificate, not supported here
			fprintf(stderr, "server asked for client cert, unsupported\n");
			servInfoult = -1;
			break;
		}
		else if (sec == SEC_I_CONTINUE_NEEDED)
		{
			// need to send data to server
			char* buffer = (char*)outbuffers[0].pvBuffer;
			int size = outbuffers[0].cbBuffer;

			while (size != 0)
			{
				int d = send(currentSocket->sock, buffer, size, 0);
				if (d <= 0)
				{
					break;
				}
				size -= d;
				buffer += d;
			}
			FreeContextBuffer(outbuffers[0].pvBuffer);
			if (size != 0)
			{
				// failed to fully send data to server
				fprintf(stderr, "Could not fully send data to server.\n");
				servInfoult = -1;
				break;
			}
		}
		else if (sec != SEC_E_INCOMPLETE_MESSAGE)
		{
			// SEC_E_CERT_EXPIRED - certificate expired or revoked
			// SEC_E_WRONG_PRINCIPAL - bad hostname
			// SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
			// SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
			servInfoult = -1;
			break;
		}

		// read more data from server when possible
		if (currentSocket->received == sizeof(currentSocket->incoming))
		{
			// server is sending too much data instead of proper handshake?
			servInfoult = -1;
			break;
		}

		int r = recv(currentSocket->sock, currentSocket->incoming + currentSocket->received, sizeof(currentSocket->incoming) - currentSocket->received, 0);
		if (r == 0)
		{
			// server disconnected socket
			return 0;
		}
		else if (r < 0)
		{
			// socket error
			servInfoult = -1;
			break;
		}
		currentSocket->received += r;
	}

	if (servInfoult != 0)
	{
		DeleteSecurityContext(context);
		FreeCredentialsHandle(&currentSocket->handle);
		closesocket(currentSocket->sock);
		WSACleanup();
		return servInfoult;
	}

	QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &currentSocket->sizes);
	return 0;
}

// disconnects socket & releases servInfoources (call this even if tls_write/tls_read function return error)
static void tls_disconnect(tls_socket* currentSocket)
{
	DWORD type = SCHANNEL_SHUTDOWN;

	SecBuffer inbuffers[1];
	inbuffers[0].BufferType = SECBUFFER_TOKEN;
	inbuffers[0].pvBuffer = &type;
	inbuffers[0].cbBuffer = sizeof(type);

	SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
	ApplyControlToken(&currentSocket->context, &indesc);

	SecBuffer outbuffers[1];
	outbuffers[0].BufferType = SECBUFFER_TOKEN;

	SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
	DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
	if (InitializeSecurityContextA(&currentSocket->handle, &currentSocket->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
	{
		char* buffer = (char*)outbuffers[0].pvBuffer;
		int size = outbuffers[0].cbBuffer;
		while (size != 0)
		{
			int d = send(currentSocket->sock, buffer, size, 0);
			if (d <= 0)
			{
				// ignore any failuservInfo socket will be closed anyway
				break;
			}
			buffer += d;
			size -= d;
		}
		FreeContextBuffer(outbuffers[0].pvBuffer);
	}
	shutdown(currentSocket->sock, SD_BOTH);

	DeleteSecurityContext(&currentSocket->context);
	FreeCredentialsHandle(&currentSocket->handle);
	closesocket(currentSocket->sock);
	WSACleanup();
}

// returns 0 on success or negative value on error
static int tls_write(tls_socket* currentSocket, const void* buffer, int size)
{
	while (size != 0)
	{
		int use = min(size, currentSocket->sizes.cbMaximumMessage);

		char wbuffer[TLS_MAX_PACKET_SIZE];
		assert(currentSocket->sizes.cbHeader + currentSocket->sizes.cbMaximumMessage + currentSocket->sizes.cbTrailer <= sizeof(wbuffer));

		SecBuffer buffers[3];
		buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
		buffers[0].pvBuffer = wbuffer;
		buffers[0].cbBuffer = currentSocket->sizes.cbHeader;
		buffers[1].BufferType = SECBUFFER_DATA;
		buffers[1].pvBuffer = wbuffer + currentSocket->sizes.cbHeader;
		buffers[1].cbBuffer = use;
		buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
		buffers[2].pvBuffer = wbuffer + currentSocket->sizes.cbHeader + use;
		buffers[2].cbBuffer = currentSocket->sizes.cbTrailer;

		CopyMemory(buffers[1].pvBuffer, buffer, use);

		SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
		SECURITY_STATUS sec = EncryptMessage(&currentSocket->context, 0, &desc, 0);
		if (sec != SEC_E_OK)
		{
			// this should not happen, but just in case check it
			return -1;
		}

		int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
		int sent = 0;
		while (sent != total)
		{
			int d = send(currentSocket->sock, wbuffer + sent, total - sent, 0);
			if (d <= 0)
			{
				// error sending data to socket, or server disconnected
				return -1;
			}
			sent += d;
		}

		buffer = (char*)buffer + use;
		size -= use;
	}

	return 0;
}

// blocking read, waits & reads up to size bytes, returns amount of bytes received on success (<= size)
// returns 0 on disconnect or negative value on error
static int tls_read(tls_socket* currentSocket, void* buffer, int size)
{
	int servInfoult = 0;

	while (size != 0)
	{
		if (currentSocket->decrypted)
		{
			// if there is decrypted data available, then use it as much as possible
			int use = min(size, currentSocket->available);
			CopyMemory(buffer, currentSocket->decrypted, use);
			buffer = (char*)buffer + use;
			size -= use;
			servInfoult += use;

			if (use == currentSocket->available)
			{
				// all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
				MoveMemory(currentSocket->incoming, currentSocket->incoming + currentSocket->used, currentSocket->received - currentSocket->used);
				currentSocket->received -= currentSocket->used;
				currentSocket->used = 0;
				currentSocket->available = 0;
				currentSocket->decrypted = NULL;
			}
			else
			{
				currentSocket->available -= use;
				currentSocket->decrypted += use;
			}
		}
		else
		{
			// if any ciphertext data available then try to decrypt it
			if (currentSocket->received != 0)
			{
				SecBuffer buffers[4];
				assert(currentSocket->sizes.cBuffers == ARRAYSIZE(buffers));

				buffers[0].BufferType = SECBUFFER_DATA;
				buffers[0].pvBuffer = currentSocket->incoming;
				buffers[0].cbBuffer = currentSocket->received;
				buffers[1].BufferType = SECBUFFER_EMPTY;
				buffers[2].BufferType = SECBUFFER_EMPTY;
				buffers[3].BufferType = SECBUFFER_EMPTY;

				SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

				SECURITY_STATUS sec = DecryptMessage(&currentSocket->context, &desc, 0, NULL);
				if (sec == SEC_E_OK)
				{
					assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
					assert(buffers[1].BufferType == SECBUFFER_DATA);
					assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

					currentSocket->decrypted = (char*)buffers[1].pvBuffer;
					currentSocket->available = buffers[1].cbBuffer;
					currentSocket->used = currentSocket->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

					// data is now decrypted, go back to beginning of loop to copy memory to output buffer
					continue;
				}
				else if (sec == SEC_I_CONTEXT_EXPIRED)
				{
					// server closed TLS connection (but socket is still open)
					currentSocket->received = 0;
					return servInfoult;
				}
				else if (sec == SEC_I_RENEGOTIATE)
				{
					// server wants to renegotiate TLS connection, not implemented here
					return -1;
				}
				else if (sec != SEC_E_INCOMPLETE_MESSAGE)
				{
					// some other schannel or TLS protocol error
					return -1;
				}
				// otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
			}
			// otherwise not enough data received to decrypt

			if (servInfoult != 0)
			{
				// some data is already copied to output buffer, so return that before blocking with recv
				break;
			}

			if (currentSocket->received == sizeof(currentSocket->incoming))
			{
				// server is sending too much garbage data instead of proper TLS packet
				return -1;
			}

			// wait for more ciphertext data from server
			int r = recv(currentSocket->sock, currentSocket->incoming + currentSocket->received, sizeof(currentSocket->incoming) - currentSocket->received, 0);
			if (r == 0)
			{
				// server disconnected socket
				return 0;
			}
			else if (r < 0)
			{
				// error receiving data from socket
				servInfoult = -1;
				break;
			}
			currentSocket->received += r;
		}
	}

	return servInfoult;
}

int main()
{
	//const char* hostname = "www.google.com";
	//const char* hostname = "badssl.com";
	//const char* hostname = "expired.badssl.com";
	//const char* hostname = "wrong.host.badssl.com";
	//const char* hostname = "self-signed.badssl.com";
	//const char* hostname = "untrusted-root.badssl.com";
	const char* hostname = "172.20.154.83";
	unsigned short port = 9785;
	const char* path = "/";

	tls_socket socket;
	if (tls_connect(&socket, hostname, port) != 0)
	{
		printf("Error connecting to %s\n", hostname);
		return -1;
	}

	printf("Connected!\n");

	// send request
	char req[1024];
	int len = sprintf(req, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname);
	if (tls_write(&socket, req, len) != 0)
	{
		tls_disconnect(&socket);
		return -1;
	}

	// write servInfoponse to file
	FILE* f = fopen("servInfoponse.txt", "wb");
	int received = 0;
	for (;;)
	{
		char buf[65536];
		int r = tls_read(&socket, buf, sizeof(buf));
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

	tls_disconnect(&socket);
}


