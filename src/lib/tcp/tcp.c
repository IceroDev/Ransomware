#include "tcp.h"

#include <arpa/inet.h>
#include <unistd.h>

/**
 * Create a new TCP socket.
 * @return Socket ID created (-1 if error) (int)
 */
int newSocketId(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}

/**
 * Create a new socket address.
 * @param ip Ip to use (const char *)
 * @param port Port to use (const unsigned int)
 * @return Socket address created (SocketAddress)
 */
SocketAddress newSocketAddress(const char *ip, const unsigned int port) {
    SocketAddress socket_address;
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port);
    socket_address.sin_addr.s_addr = inet_addr(ip);

    return socket_address;
}

/**
 * Bind a socket on the machine (reserve a port on it).
 * @param socket_id Socket id to bind (const int *)
 * @param socket_address Socket address used for the binding (SocketAddress *)
 * @return Success of the binding (bool)
 */
bool bindSocket(const int *socket_id, SocketAddress *socket_address) {
    return bind(*socket_id, (const struct sockaddr *) socket_address, sizeof(*socket_address)) == 0;
}

/**
 * Listen on a socket id.
 * @param socket_id Socket id to listen (const int *)
 * @param connexion Max connexions to listen at the same time (const int)
 * @return True if the socket can listen, false otherwise (bool)
 */
bool listenServer(const int *socket_id, const int connexion) {
    return listen(*socket_id, connexion) == 0;
}

/**
 * Wait for a connexion and open a socket id.
 * @param socket_id Socket id that can listen (const int *)
 * @param from_socket_address Incoming socket address (SocketAddress *)
 * @param from_socket_address_size Size of the incoming socket address (socklen_t *)
 * @return The socket id created to communicate with the client (-1 if error) (int)
 */
int waitConnexion(const int *socket_id, SocketAddress *from_socket_address, socklen_t *from_socket_address_size) {
    return accept(*socket_id, (struct sockaddr *) from_socket_address, from_socket_address_size);
}

/**
 * Connect a client to the server.
 * @param socket_id Socket id used for the connection (const int *)
 * @param socket_address Server socket address (SocketAddress *)
 * @return Success of the operation (bool)
 */
bool connectClient(const int *socket_id, SocketAddress *socket_address) {
    return connect(*socket_id, (struct sockaddr *) socket_address, sizeof(*socket_address)) == 0;
}

/**
 * Receive data from a client.
 * @param from_socket_id Socket id of the client (const int *)
 * @param buffer Buffer used for the received data (char *)
 * @param buffer_size Max size that the buffer can contains (const size_t)
 * @return Number of bytes read (-1 if error) (ssize_t)
 */
ssize_t receiveData(const int *from_socket_id, char *buffer, const size_t buffer_size) {
    return recv(*from_socket_id, buffer, buffer_size, MSG_WAITALL);
}

/**
 * Send data to the server.
 * @param socket_id Client socket id (const int *)
 * @param buffer Buffer containing the data to send (char *)
 * @param buffer_size Size of the buffer (const size_t)
 * @return Number of bytes sent (-1 if error) (ssize_t)
 */
ssize_t sendData(const int *socket_id, char *buffer, const size_t buffer_size) {
    return send(*socket_id, buffer, buffer_size, MSG_OOB);
}

/**
 * Close a socket id.
 * @param socket_id Socket id to close (const int *)
 */
void closeSocketAddress(const int *socket_id) {
    close(*socket_id);
}