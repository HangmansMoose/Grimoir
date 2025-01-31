// #include <windows.h>
// #include <winsock2.h>
// #include <ws2tcpip.h>
// #include <mswsock.h>
// #include <schannel.h>
// #include <iostream>
// #include <vector>
// #include <sstream>
// #include <thread>

// #pragma comment(lib, "ws2_32.lib")
// #pragma comment(lib, "secur32.lib")

// void InitializeWinsock() {
//     WSADATA wsaData;
//     int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
//     if (result != 0) {
//         std::cerr << "WSAStartup failed: " << result << std::endl;
//         exit(1);
//     }
// }

// SOCKET ConnectToServer(const std::string& host, const std::string& port) {
//     addrinfo hints = {}, *res;
//     hints.ai_family = AF_INET;
//     hints.ai_socktype = SOCK_STREAM;
//     hints.ai_protocol = IPPROTO_TCP;

//     if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
//         std::cerr << "getaddrinfo failed" << std::endl;
//         WSACleanup();
//         exit(1);
//     }

//     SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//     if (sock == INVALID_SOCKET) {
//         std::cerr << "Socket creation failed" << std::endl;
//         freeaddrinfo(res);
//         WSACleanup();
//         exit(1);
//     }

//     if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
//         std::cerr << "Connection failed" << std::endl;
//         closesocket(sock);
//         freeaddrinfo(res);
//         WSACleanup();
//         exit(1);
//     }
    
//     freeaddrinfo(res);
//     return sock;
// }

// void PerformTLSHandshake(SOCKET sock) {
//     // Placeholder for full TLS handshake using SChannel
//     std::cout << "Performing TLS handshake..." << std::endl;
//     // TLS handshake logic should be implemented here
// }

// void WebSocketHandshake(SOCKET sock) {
//     std::stringstream request;
//     request << "GET / HTTP/1.1\r\n";
//     request << "Host: your.websocketserver.com\r\n";
//     request << "Upgrade: websocket\r\n";
//     request << "Connection: Upgrade\r\n";
//     request << "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
//     request << "Sec-WebSocket-Version: 13\r\n";
//     request << "\r\n";
    
//     std::string reqStr = request.str();
//     send(sock, reqStr.c_str(), reqStr.size(), 0);
    
//     char response[1024];
//     recv(sock, response, sizeof(response), 0);
//     std::cout << "WebSocket handshake response:\n" << response << std::endl;
// }

// void ReceiveMessages(SOCKET sock) {
//     char buffer[1024];
//     while (true) {
//         int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
//         if (bytesReceived > 0) {
//             buffer[bytesReceived] = '\0';
//             std::cout << "Received: " << buffer << std::endl;
//         }
//     }
// }

// void SendMessages(SOCKET sock) {
//     std::string message;
//     while (true) {
//         std::cout << "Enter message: ";
//         std::getline(std::cin, message);
//         if (message == "exit") break;
//         send(sock, message.c_str(), message.size(), 0);
//     }
// }

// void SecureWebSocketCommunication(SOCKET sock) {
//     PerformTLSHandshake(sock);
//     WebSocketHandshake(sock);
//     std::cout << "Connected securely. Ready to send and receive messages." << std::endl;
    
//     std::thread receiveThread(ReceiveMessages, sock);
//     SendMessages(sock);
//     // Detaching the thread stops it from being a blocking thread and makes the OS responsible for 
//     // cleaning up the resources when it is complete
//     receiveThread.detach();
// }

// int main() {
//     InitializeWinsock();
//     SOCKET sock = ConnectToServer("your.websocketserver.com", "443");
//     SecureWebSocketCommunication(sock);
//     closesocket(sock);
//     WSACleanup();
//     return 0;
// }
