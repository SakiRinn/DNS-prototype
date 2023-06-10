/**
 * @file records.h
 * @brief Encapsulations of UNIX network programming functions.
 *
 * All functions are named according to the UNIX function naming conventions.
 */
#ifndef SOCKET_H
#define SOCKET_H

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 1024
#define LISTEN_BACKLOG 20

/**
 * @brief Bind a socket to a local address
 * @param sock The socket to bind
 * @param addr The structure of IPv4 address
 */
void server_bind(int sock, struct sockaddr_in *addr);
/**
 * @brief Set the port reuseable.
 * @param sock The socket to set
 */
void set_socket_reuse(int sock);

/**
 * UDP Socket Encapsulation
 */
int udp_socket();
void udp_send(int sock, struct sockaddr_in *dest_addr, char *buffer,
              size_t buffer_len);
ssize_t udp_receive(int sock, struct sockaddr_in *client_addr, char *buffer);

/**
 * TCP Socket Encapsulation
 */
int tcp_socket();
void tcp_connect(int sock, struct sockaddr_in *addr);
void tcp_listen(int sock);
int tcp_accept(int sock, struct sockaddr_in *client_addr);
void tcp_send(int client_sock, char *buffer, size_t buffer_len);
ssize_t tcp_receive(int client_sock, char *buffer);

#endif