#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef WIN32_LEAN_AND_MEAN
	#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include "WebSocket.h"

bool WebSocket::Init()
{
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0)
	{
        return false;
	}

	return true;
}

int WebSocket::tls_connect(tls_socket* s, const char* hostname, unsigned short port)
{
   // initialize windows sockets

   // create TCP IPv4 socket
   s->socket = socket(AF_INET, SOCK_STREAM, 0);
   if (s->socket == INVALID_SOCKET)
   {
       WSACleanup();
       return -1;
   }

   char sport[64];
   wnsprintfA(sport, sizeof(sport), "%u", port);

   // connect to server
   if (!WSAConnectByNameA(s->socket, hostname, sport, NULL, NULL, NULL, NULL, NULL, NULL))
   {
       closesocket(s->socket);
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
   

   if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &s->handle, NULL) != SEC_E_OK)
   {
       closesocket(s->socket);
       WSACleanup();
       return -1;
   }
   

   s->received = s->used = s->available = 0;
   s->decrypted = NULL;

   // perform tls handshake
   // 1) call InitializeSecurityContext to create/update schannel context
   // 2) when it returns SEC_E_OK - tls handshake completed
   // 3) when it returns SEC_I_INCOMPLETE_CREDENTIALS - server requests client certificate (not supported here)
   // 4) when it returns SEC_I_CONTINUE_NEEDED - send token to server and read data
   // 5) when it returns SEC_E_INCOMPLETE_MESSAGE - need to read more data from server
   // 6) otherwise read data from server and go to step 1

   CtxtHandle* context = NULL;
   int result = 0;
   for (;;)
   {
       SecBuffer inbuffers[2] = { 0 };
       inbuffers[0].BufferType = SECBUFFER_TOKEN;
       inbuffers[0].pvBuffer = s->incoming;
       inbuffers[0].cbBuffer = s->received;
       inbuffers[1].BufferType = SECBUFFER_EMPTY;

       SecBuffer outbuffers[1] = { 0 };
       outbuffers[0].BufferType = SECBUFFER_TOKEN;

       SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
       SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

       DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
       SECURITY_STATUS sec = InitializeSecurityContextA(
           &s->handle,
           context,
           context ? NULL : (SEC_CHAR*)hostname,
           flags,
           0,
           0,
           context ? &indesc : NULL,
           0,
           context ? NULL : &s->context,
           &outdesc,
           &flags,
           NULL);

       // after first call to InitializeSecurityContext context is available and should be reused for next calls
       context = &s->context;

       if (inbuffers[1].BufferType == SECBUFFER_EXTRA)
       {
           MoveMemory(s->incoming, s->incoming + (s->received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
           s->received = inbuffers[1].cbBuffer;
       }
       else
       {
           s->received = 0;
       }

       if (sec == SEC_E_OK)
       {
           // tls handshake completed
           break;
       }
       else if (sec == SEC_I_INCOMPLETE_CREDENTIALS)
       {
           // server asked for client certificate, not supported here
           result = -1;
           break;
       }
       else if (sec == SEC_I_CONTINUE_NEEDED)
       {
           // need to send data to server
           char* buffer = (char*)outbuffers[0].pvBuffer;
           int size = outbuffers[0].cbBuffer;

           while (size != 0)
           {
               int d = send(s->socket, buffer, size, 0);
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
               result = -1;
               break;
           }
       }
       else if (sec != SEC_E_INCOMPLETE_MESSAGE)
       {
           // SEC_E_CERT_EXPIRED - certificate expired or revoked
           // SEC_E_WRONG_PRINCIPAL - bad hostname
           // SEC_E_UNTRUSTED_ROOT - cannot vertify CA chain
           // SEC_E_ILLEGAL_MESSAGE / SEC_E_ALGORITHM_MISMATCH - cannot negotiate crypto algorithms
           result = -1;
           break;
       }

       // read more data from server when possible
       if (s->received == sizeof(s->incoming))
       {
           // server is sending too much data instead of proper handshake?
           result = -1;
           break;
       }

       int r = recv(s->socket, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
       if (r == 0)
       {
           // server disconnected socket
           return 0;
       }
       else if (r < 0)
       {
           // socket error
           result = -1;
           break;
       }
       s->received += r;
   }

   if (result != 0)
   {
       DeleteSecurityContext(context);
       FreeCredentialsHandle(&s->handle);
       closesocket(s->socket);
       WSACleanup();
       return result;
   }

   QueryContextAttributes(context, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
   return 0;
}

// disconnects socket & releases resources (call this even if tls_write/tls_read function return error)
void WebSocket::tls_disconnect(tls_socket* s)
{
   DWORD type = SCHANNEL_SHUTDOWN;

   SecBuffer inbuffers[1];
   inbuffers[0].BufferType = SECBUFFER_TOKEN;
   inbuffers[0].pvBuffer = &type;
   inbuffers[0].cbBuffer = sizeof(type);

   SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
   ApplyControlToken(&s->context, &indesc);

   SecBuffer outbuffers[1];
   outbuffers[0].BufferType = SECBUFFER_TOKEN;

   SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
   DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
   if (InitializeSecurityContextA(&s->handle, &s->context, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
   {
       char* buffer = (char *)outbuffers[0].pvBuffer;
       int size = outbuffers[0].cbBuffer;
       while (size != 0)
       {
           int d = send(s->socket, buffer, size, 0);
           if (d <= 0)
           {
               // ignore any failures socket will be closed anyway
               break;
           }
           buffer += d;
           size -= d;
       }
       FreeContextBuffer(outbuffers[0].pvBuffer);
   }
   shutdown(s->socket, SD_BOTH);

   DeleteSecurityContext(&s->context);
   FreeCredentialsHandle(&s->handle);
   closesocket(s->socket);
   WSACleanup();
}

// returns 0 on success or negative value on error
int WebSocket::tls_write(tls_socket* s, const void* buffer, int size)
{
   while (size != 0)
   {
       int use = min(size, s->sizes.cbMaximumMessage);

       char wbuffer[TLS_MAX_PACKET_SIZE];
       assert(s->sizes.cbHeader + s->sizes.cbMaximumMessage + s->sizes.cbTrailer <= sizeof(wbuffer));

       SecBuffer buffers[3];
       buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
       buffers[0].pvBuffer = wbuffer;
       buffers[0].cbBuffer = s->sizes.cbHeader;
       buffers[1].BufferType = SECBUFFER_DATA;
       buffers[1].pvBuffer = wbuffer + s->sizes.cbHeader;
       buffers[1].cbBuffer = use;
       buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
       buffers[2].pvBuffer = wbuffer + s->sizes.cbHeader + use;
       buffers[2].cbBuffer = s->sizes.cbTrailer;

       CopyMemory(buffers[1].pvBuffer, buffer, use);

       SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
       SECURITY_STATUS sec = EncryptMessage(&s->context, 0, &desc, 0);
       if (sec != SEC_E_OK)
       {
           // this should not happen, but just in case check it
           return -1;
       }

       int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
       int sent = 0;
       while (sent != total)
       {
           int d = send(s->socket, wbuffer + sent, total - sent, 0);
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
int WebSocket::tls_read(tls_socket* s, void* buffer, int size)
{
   int result = 0;

   while (size != 0)
   {
       if (s->decrypted)
       {
           // if there is decrypted data available, then use it as much as possible
           int use = min(size, s->available);
           CopyMemory(buffer, s->decrypted, use);
           buffer = (char*)buffer + use;
           size -= use;
           result += use;

           if (use == s->available)
           {
               // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
               MoveMemory(s->incoming, s->incoming + s->used, s->received - s->used);
               s->received -= s->used;
               s->used = 0;
               s->available = 0;
               s->decrypted = NULL;
           }
           else
           {
               s->available -= use;
               s->decrypted += use;
           }
       }
       else
       {
           // if any ciphertext data available then try to decrypt it
           if (s->received != 0)
           {
               SecBuffer buffers[4];
               assert(s->sizes.cBuffers == ARRAYSIZE(buffers));

               buffers[0].BufferType = SECBUFFER_DATA;
               buffers[0].pvBuffer = s->incoming;
               buffers[0].cbBuffer = s->received;
               buffers[1].BufferType = SECBUFFER_EMPTY;
               buffers[2].BufferType = SECBUFFER_EMPTY;
               buffers[3].BufferType = SECBUFFER_EMPTY;

               SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

               SECURITY_STATUS sec = DecryptMessage(&s->context, &desc, 0, NULL);
               if (sec == SEC_E_OK)
               {
                   assert(buffers[0].BufferType == SECBUFFER_STREAM_HEADER);
                   assert(buffers[1].BufferType == SECBUFFER_DATA);
                   assert(buffers[2].BufferType == SECBUFFER_STREAM_TRAILER);

                   s->decrypted = (char *)buffers[1].pvBuffer;
                   s->available = buffers[1].cbBuffer;
                   s->used = s->received - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                   // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                   continue;
               }
               else if (sec == SEC_I_CONTEXT_EXPIRED)
               {
                   // server closed TLS connection (but socket is still open)
                   s->received = 0;
                   return result;
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

           if (result != 0)
           {
               // some data is already copied to output buffer, so return that before blocking with recv
               break;
           }

           if (s->received == sizeof(s->incoming))
           {
               // server is sending too much garbage data instead of proper TLS packet
               return -1;
           }

           // wait for more ciphertext data from server
           int r = recv(s->socket, s->incoming + s->received, sizeof(s->incoming) - s->received, 0);
           if (r == 0)
           {
               // server disconnected socket
               return 0;
           }
           else if (r < 0)
           {
               // error receiving data from socket
               result = -1;
               break;
           }
           s->received += r;
       }
   }

   return result;
}
