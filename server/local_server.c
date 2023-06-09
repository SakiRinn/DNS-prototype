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
    set_socket_reuse(udp_sock);
    server_bind(udp_sock, &receive_addr);

    unsigned char buffer[BUFSIZE] = {0};
    unsigned char query_buffer[BUFSIZE] = {0};

    while (1) {
        memset(buffer, 0, BUFSIZE);
        memset(query_buffer, 0, BUFSIZE);

        dns_header *header = (dns_header *)malloc(sizeof(dns_header));
        dns_query *query = (dns_query *)malloc(sizeof(dns_query));

        int udp_recv_len = udp_receive(udp_sock, &client_addr, query_buffer);
        uint16_t length = parse_header(header, query_buffer);
        parse_query(query, query_buffer + length);

        printf("\n********* Receive a new query! *********\n");
        printf(" > Query: \t%s\n", query->domain);
        printf(" > Type: \t%s\n", type_to_string(query->type));

        memcpy(buffer, query_buffer, BUFSIZE);
        memset(query_buffer, 0, BUFSIZE);
        memcpy(query_buffer + 2, buffer, udp_recv_len);
        *((uint16_t *)query_buffer) = htons(udp_recv_len);

        dns_rr *caches;
        int cache_count = load_records(&caches, "./data/cache.txt");

        int idx;
        if (query->type == PTR) {
            char ip[DOMAIN_MAX_LENGTH] = {0}, rdomain[DOMAIN_MAX_LENGTH] = {0};
            char *origin = query->domain;
            serialize_domain(rdomain, origin);
            parse_ptr(ip, rdomain);
            free(origin);
            idx = find_rr(caches, cache_count, ip, query->type);
        } else
            idx = find_rr(caches, cache_count, query->domain, query->type);

        if (idx != -1) {
            length = udp_recv_len;
            init_header(header, header->id,
                        generate_flags(QR_RESPONSE, OP_STD, 0, R_FINE),
                        header->num_query, 1, 0, query->type == MX ? 1 : 0);
            add_header(query_buffer + 2, header);

            int a_idx = 0;
            if (query->type == A)
                length += add_ip_rr(query_buffer + 2 + length, caches + idx);
            else if (query->type == MX) {
                length +=
                    add_domain_rr(query_buffer + 2 + length, caches + idx);
                a_idx = find_a_by_domain(caches, cache_count, caches[idx].data);
                if (a_idx == -1) {
                    perror("Cache error");
                    exit(EXIT_FAILURE);
                }
                length += add_ip_rr(query_buffer + 2 + length, caches + a_idx);
            } else
                length +=
                    add_domain_rr(query_buffer + 2 + length, caches + idx);
            udp_send(udp_sock, &client_addr, query_buffer + 2, length);

            printf(" > Result: \t%s\n", caches[idx].data);
            if (query->type == MX)
                printf(" > MX IP: \t%s\n", caches[a_idx].data);
            printf(" Load from cache!\n");
            printf("****************************************\n");
            continue;
        }

        int tcp_sock = tcp_socket();
        set_socket_reuse(tcp_sock);
        server_bind(tcp_sock, &send_addr);
        tcp_connect(tcp_sock, &root_server_addr);
        tcp_send(tcp_sock, query_buffer, udp_recv_len + 2);

        printf(" > Trace to \troot (%s)\n", ROOT_SERVER_IP);

        while (1) {
            memset(buffer, 0, BUFSIZE);
            int tcp_recv_len = tcp_receive(tcp_sock, buffer);
            length = parse_header(header, buffer + 2);
            length += parse_query(query, buffer + 2 + length);

            if ((header->flags & 0xF) == R_NAME_ERROR) {
                header->flags = generate_flags(
                    QR_RESPONSE, query->type == PTR ? OP_INV : OP_STD, 0,
                    R_NAME_ERROR);
                add_header(query_buffer + 2, header);
                udp_send(udp_sock, &client_addr, query_buffer + 2,
                         udp_recv_len);
                close(tcp_sock);

                printf(" [NO Result] Fail to match the domain!\n");
                printf("****************************************\n");
                break;
            } else if (header->num_answer_rr == 0) {

                int count = header->num_authority_rr + header->num_addition_rr;
                dns_rr *records = (dns_rr *)malloc(count * sizeof(dns_rr));
                for (int i = 0; i < count; i++)
                    length += parse_rr(records + i, buffer + 2 + length);

                if (records[0].type == NS) {
                    int a_idx =
                        find_a_by_domain(records, count, records[0].data);
                    if (a_idx == -1) {
                        perror("NS forward error");
                        break;
                    } else {
                        struct sockaddr_in forward_addr;
                        init_receiver_addr(&forward_addr, records[a_idx].data);
                        printf(" > Trace to \t%s (%s)\n", records[0].data,
                               records[a_idx].data);

                        close(tcp_sock);
                        tcp_sock = tcp_socket();
                        set_socket_reuse(tcp_sock);
                        server_bind(tcp_sock, &send_addr);
                        tcp_connect(tcp_sock, &forward_addr);
                        tcp_send(tcp_sock, query_buffer, udp_recv_len + 2);

                        free_records(records, count);
                    }
                } else {
                    perror("No answer error");
                    close(tcp_sock);
                    break;
                }
            } else {
                memcpy(query_buffer + 2 + udp_recv_len, buffer + 2 + length,
                       tcp_recv_len - 2 - length);
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_STD, 0, R_FINE),
                            header->num_query, 1, 0, query->type == MX ? 1 : 0);
                add_header(query_buffer + 2, header);
                udp_send(udp_sock, &client_addr, query_buffer + 2,
                         tcp_recv_len - 2);
                close(tcp_sock);

                int num_rr = header->num_answer_rr + header->num_authority_rr +
                             header->num_addition_rr;
                dns_rr *rr = (dns_rr *)malloc(sizeof(dns_rr));
                length = udp_recv_len;
                for (int i = 0; i < num_rr; i++) {
                    length += parse_rr(rr, buffer + 2 + length);
                    save_rr(*rr, "./data/cache.txt");
                }
                printf(" > Result: \t%s\n", rr->data);
                printf(" Success to add %d new cache record(s).\n", num_rr);
                printf("****************************************\n");
                break;
            }
        }
    }
    close(udp_sock);
}