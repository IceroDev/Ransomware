#ifndef RANSOMWARE_TCP_H
#define RANSOMWARE_TCP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>

#define TCP_SERVER_IP "127.0.0.1"
#define TCP_SERVER_PORT 8888

// Because of the max path file length
#define TCP_BUFFER_SIZE 4096

typedef struct sockaddr_in SocketAddress;

int newSocketId(void);

SocketAddress newSocketAddress(const char *ip, unsigned int port);

bool bindSocket(const int *socket_id, SocketAddress *socket_address);

bool listenServer(const int *socket_id, int connexion);

int waitConnexion(const int *socket_id, SocketAddress *from_socket_address, socklen_t *from_socket_address_size);

bool connectClient(const int *socket_id, SocketAddress *socket_address);

ssize_t receiveData(const int *from_socket_id, char *buffer, size_t buffer_size);

ssize_t sendData(const int *socket_id, char *buffer, size_t buffer_size);

void closeSocketAddress(const int *socket_id);

#endif //RANSOMWARE_TCP_H
