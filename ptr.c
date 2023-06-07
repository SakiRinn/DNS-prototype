#include "data.h"
#include "dns.h"
#include "records.h"
#include "socket.h"
#include <stdlib.h>
#include <string.h>

int main() {
    struct sockaddr_in local_server_addr;
    struct sockaddr_in ptr_addr;
    init_receiver_addr(&ptr_addr, PTR_SERVER_IP);

    int sock = tcp_socket();
    set_socket_reuse(sock);
    server_bind(sock, &ptr_addr);
    tcp_listen(sock);

    dns_rr *records;
    int count = load_records(&records, "./data/ptr.txt");

    while (1) {
        int client_sock = tcp_accept(sock, &local_server_addr);
        set_socket_reuse(client_sock);
        unsigned char buffer[BUFSIZE] = {0};

        int receive_len = 0;
        while (receive_len = tcp_receive(client_sock, buffer)) {
            dns_header *header = (dns_header *)malloc(sizeof(dns_header));
            dns_query *query = (dns_query *)malloc(sizeof(dns_query));

            uint16_t length = parse_header(header, buffer + 2);
            parse_query(query, buffer + 2 + length);
            memset(buffer, 0, BUFSIZE);

            printf("\n********* Receive a new query! *********\n");
            printf(" > Query: \t%s\n", query->domain);

            char ip[DOMAIN_MAX_LENGTH] = {0};
            char *rdomain = query->domain;
            parse_ptr(ip, query->domain);
            query->domain = malloc(strlen(ip) + 1);
            strcpy(query->domain, ip);
            free(rdomain);

            length = 0;
            int idx = find_rr(records, count, query->domain, query->type);
            if (idx != -1) {
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_INV, 0, R_FINE),
                            header->num_query, 1, 0, query->type == MX ? 1 : 0);
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                length += add_domain_rr(buffer + 2 + length, records + idx);
                *((uint16_t *)buffer) = htons(length);

                printf(" > Result: \t%s\n", records[idx].data);
                printf("****************************************\n");
            } else {
                init_header(
                    header, header->id,
                    generate_flags(QR_RESPONSE, OP_INV, 0, R_NAME_ERROR),
                    header->num_query, 0, 0, 0);
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((uint16_t *)buffer) = htons(length);
                printf(" [NO Result] Fail to match the domain!\n");
                printf("****************************************\n");
            }
            free(header);
            free_query(query);
            tcp_send(client_sock, buffer, length + 2);
            break;
        }
        close(client_sock);
    }
    free_records(records, count);
    close(sock);
}