#ifndef SOCKET_H_
#define SOCKET_H_

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 1024
#define LISTEN_BACKLOG 20

void server_bind(int sock, struct sockaddr_in *addr);

int udp_socket();
void udp_send(int sock, struct sockaddr_in *dest_addr, char *buffer,
              size_t buffer_len);
ssize_t udp_receive(int sock, struct sockaddr_in *client_addr, char *buffer);

int tcp_socket();
void tcp_connect(int sock, struct sockaddr_in *addr);
void tcp_listen(int sock);
int tcp_accept(int sock, struct sockaddr_in *client_addr);
void tcp_send(int client_sock, char *buffer, size_t buffer_len);
ssize_t tcp_receive(int client_sock, char *buffer);

#endif