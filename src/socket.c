#include "socket.h"

void server_bind(int sock, struct sockaddr_in *addr) {
    if (bind(sock, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) < 0) {
        perror("Bind failed");
    }
}

void set_socket_reuse(int sock) {
    int val = 1;
    int ret =
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&val, sizeof(int));
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
    if (receive_len == -1) {
        perror("UDP receive failed");
        exit(EXIT_FAILURE);
    }
    return receive_len;
}

int tcp_socket() {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Creating TCP socket failed");
        close(sock);
    }
    return sock;
}

void tcp_connect(int sock, struct sockaddr_in *dest_addr) {
    if (connect(sock, (struct sockaddr *)dest_addr,
                sizeof(struct sockaddr_in)) == -1) {
        perror("TCP connection failed");
        exit(EXIT_FAILURE);
    }
}

void tcp_listen(int sock) {
    if (listen(sock, LISTEN_BACKLOG) == -1) {
        perror("TCP setting listen mode failed");
        exit(EXIT_FAILURE);
    }
}

int tcp_accept(int sock, struct sockaddr_in *client_addr) {
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int client_sock =
        accept(sock, (struct sockaddr *)client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("TCP accept failed");
        exit(EXIT_FAILURE);
    }
    return client_sock;
}

void tcp_send(int client_sock, char *buffer, size_t buffer_len) {
    if (send(client_sock, buffer, buffer_len, 0) != buffer_len) {
        perror("TCP send failed");
    }
}

ssize_t tcp_receive(int client_sock, char *buffer) {
    ssize_t receive_len = recv(client_sock, buffer, BUFSIZE, 0);
    if (receive_len == -1) {
        perror("receive failed!");
        exit(EXIT_FAILURE);
    } else if (receive_len == 0) {
        printf("TCP disconnected with client\n");
    }
    return receive_len;
}