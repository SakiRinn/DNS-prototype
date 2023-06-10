#include "socket.h"

void server_bind(int sock, struct sockaddr_in *addr) {
    // Bind sock sockaddr (converted from sockaddr_in)
    if (bind(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Bind failed");
    }
}

void set_socket_reuse(int sock) {
    int val = 1;
    int ret =
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(int));
    // If failed, exit.
    if (ret == -1) {
        printf("setsockopt");
        exit(1);
    }
}

int udp_socket() {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Creating UDP socket failed");
        close(sock);
    }
    return sock;
}

void udp_send(int sock, struct sockaddr_in *dest_addr, char *buffer,
              size_t buffer_len) {
    if (sendto(sock, buffer, buffer_len, 0, (struct sockaddr *)dest_addr,
               sizeof(struct sockaddr_in)) != buffer_len) {
        perror("UDP send failed");
    }
}

ssize_t udp_receive(int sock, struct sockaddr_in *client_addr, char *buffer) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    ssize_t receive_len =
        recvfrom(sock, buffer, BUFSIZE, 0, (struct sockaddr *)client_addr,
                 &client_addr_len);
    // UDP receive data received from the server
    if (receive_len == -1) {
        perror("UDP receive failed");
        exit(EXIT_FAILURE);
    }
    return receive_len;
}

/**
* @brief Create a TCP socket.
* @return socket on success - 1 on
*/
int tcp_socket() {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    // Creates a new TCP socket.
    if (sock < 0) {
        perror("Creating TCP socket failed");
        close(sock);
    }
    return sock;
}

/**
* @brief Connects a socket to a destination
* @param sock the socket to connect to
* @param dest_addr the address to connect
*/
void tcp_connect(int sock, struct sockaddr_in *dest_addr) {
    // Connect to the TCP server.
    if (connect(sock, (struct sockaddr *)dest_addr,
                sizeof(struct sockaddr_in)) == -1) {
        perror("TCP connection failed");
        exit(EXIT_FAILURE);
    }
}

/**
* @brief Set listen mode on socket
* @param sock socket to set listen
*/
void tcp_listen(int sock) {
    // listen for TCP connections on the socket
    if (listen(sock, LISTEN_BACKLOG) == -1) {
        perror("TCP setting listen mode failed");
        exit(EXIT_FAILURE);
    }
}

/**
* @brief Accepts a connection on the socket.
* @param sock The socket to accept on
* @param client_addr * A pointer to an address to store the address of the client
* @return Returns the socket on success - 1 on
*/
int tcp_accept(int sock, struct sockaddr_in *client_addr) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int client_sock =
        accept(sock, (struct sockaddr *)client_addr, &client_addr_len);
    // accepts a TCP accept request.
    if (client_sock == -1) {
        perror("TCP accept failed");
        exit(EXIT_FAILURE);
    }
    return client_sock;
}

/**
* @brief Send data over a TCP socket
* @param client_sock Socket to send data over
* @param buffer Buffer containing data to send
* @param buffer_len Length of the data
*/
void tcp_send(int client_sock, char *buffer, size_t buffer_len) {
    // Send a packet to the client.
    if (send(client_sock, buffer, buffer_len, 0) != buffer_len) {
        perror("TCP send failed");
    }
}

/**
* @brief Receive data from client.
* @param client_sock socket to receive data from
* @param buffer * buffer to store received data
* @return number of bytes received or - 1 on
*/
ssize_t tcp_receive(int client_sock, char *buffer) {
    ssize_t receive_len = recv(client_sock, buffer, BUFSIZE, 0);
    // receive_len 0 if receive_len 0 exit with exit code EXIT_FAILURE
    if (receive_len == -1) {
        perror("receive failed!");
        exit(EXIT_FAILURE);
    // if receive_len 0 print out the message
    } else if (receive_len == 0) {
        printf("TCP disconnected with client\n");
    }
    return receive_len;
}