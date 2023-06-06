#include "data.h"
#include "dns.h"
#include "records.h"
#include "socket.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main() {
    struct sockaddr_in client_addr;
    init_receiver_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in receive_addr;
    init_receiver_addr(&receive_addr, LOCAL_SERVER_IP);
    struct sockaddr_in send_addr;
    init_sender_addr(&send_addr, LOCAL_SERVER_IP);
    struct sockaddr_in root_server_addr;
    init_receiver_addr(&root_server_addr, ROOT_SERVER_IP);

    int udp_sock = udp_socket();
    server_bind(udp_sock, &receive_addr);

    unsigned char buffer[BUFSIZE] = {0};
    unsigned char query_buffer[BUFSIZE] = {0};

    while (1) {
        memset(buffer, 0, BUFSIZE);
        memset(query_buffer, 0, BUFSIZE);

        dns_header *header = (dns_header *)malloc(sizeof(dns_header));
        dns_query *query = (dns_query *)malloc(sizeof(dns_query));

        int udp_recv_len = udp_receive(udp_sock, &client_addr, query_buffer);
        uint16_t length = parse_header(header, buffer);
        parse_query(query, buffer + length);

        memcpy(buffer, query_buffer, BUFSIZE);
        memset(query_buffer, 0, BUFSIZE);
        memcpy(query_buffer, buffer + 2, udp_recv_len);
        *((uint16_t *)query_buffer) = htons(udp_recv_len);

        int tcp_sock = tcp_socket();
        server_bind(tcp_sock, &send_addr);
        tcp_connect(tcp_sock, &root_server_addr);
        tcp_send(tcp_sock, query_buffer, udp_recv_len + 2);

        while (1) {
            memset(buffer, 0, BUFSIZE);
            int tcp_recv_len = tcp_receive(tcp_sock, buffer);
            length = parse_header(header, buffer + 2);
            length += parse_query(query, buffer + 2 + length);
            close(tcp_sock);

            if (header->flags % 0xF == R_NAME_ERROR) {
                udp_send(udp_sock, &client_addr, query_buffer + 2,
                         udp_recv_len);
                break;
            } else if (header->num_answer_rr == 0) {
                int count = header->num_authority_rr + header->num_addition_rr;
                dns_rr *records = (dns_rr *)malloc(count * sizeof(dns_rr));
                for (int i = 0; i < count; i++)
                    length += parse_rr(records, buffer + 2 + length);

                if (records[0].type == NS) {
                    int a_idx =
                        find_a_by_domain(records, count, records[0].data);
                    if (a_idx == -1) {
                        perror("NS forward error!");
                        break;
                    } else {
                        struct sockaddr_in forward_addr;
                        init_receiver_addr(&forward_addr, records[a_idx].data);
                        tcp_connect(tcp_sock, &forward_addr);
                        tcp_send(tcp_sock, query_buffer, udp_recv_len + 2);
                        for (int i = 0; i < count; i++)
                            free_rr(records + i);
                    }
                } else {
                    perror("No answer error!");
                    break;
                }
            } else {
                add_header(query_buffer + 2, header);
                memcpy(query_buffer + 2 + udp_recv_len, buffer + 2 + length,
                       tcp_recv_len - 2 - length);
                udp_send(udp_sock, &client_addr, query_buffer + 2,
                         tcp_recv_len - 2);
                break;
            }
        }
    }

    close(udp_sock);
}