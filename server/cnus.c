#include "data.h"
#include "dns.h"
#include "records.h"
#include "socket.h"
#include <stdio.h>
#include <string.h>

int main() {
    // Init address.
    struct sockaddr_in local_server_addr;
    struct sockaddr_in cnus_addr;
    init_receiver_addr(&cnus_addr, CNUS_SERVER_IP);

    // Create TCP socket and set to the listen mode.
    int sock = tcp_socket();
    set_socket_reuse(sock);
    server_bind(sock, &cnus_addr);
    tcp_listen(sock);

    // Load data.
    dns_rr *records;
    int count = load_records(&records, "./data/cnus.txt");

    while (1) {
        // Accept a new connection.
        int client_sock = tcp_accept(sock, &local_server_addr);
        unsigned char buffer[BUFSIZE] = {0};

        // Deal with the received information.
        int receive_len = 0;
        while (receive_len = tcp_receive(client_sock, buffer)) {
            dns_header *header = (dns_header *)malloc(sizeof(dns_header));
            dns_query *query = (dns_query *)malloc(sizeof(dns_query));

            uint16_t length = parse_header(header, buffer + 2);
            parse_query(query, buffer + 2 + length);
            memset(buffer, 0, BUFSIZE);

            printf("\n********* Receive a new query! *********\n");
            printf(" > Query: \t%s\n", query->domain);
            printf(" > Type: \t%s\n", type_to_string(query->type));

            /**
             * Query Part
             */
            length = 0;
            int ns_idx = find_ns_by_query(records, count, query);
            if (ns_idx != -1) {
                // If found ?
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_STD, 1, R_FINE),
                            header->num_query, 0, 1, 1);
                int a_idx = find_rr(records, count, records[ns_idx].data, A);
                if (a_idx == -1) {
                    perror("Database error");
                    exit(EXIT_FAILURE);
                }

                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                length += add_domain_rr(buffer + 2 + length, records + ns_idx);
                length += add_ip_rr(buffer + 2 + length, records + a_idx);
                *((uint16_t *)buffer) = htons(length);

                printf(" > NS Domain: \t%s\n", records[ns_idx].data);
                printf(" > NS IP: \t%s\n", records[a_idx].data);
                printf("****************************************\n");
            } else {
                // If not found ?
                init_header(
                    header, header->id,
                    generate_flags(QR_RESPONSE, OP_STD, 1, R_NAME_ERROR),
                    header->num_query, 0, 0, 0);

                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((uint16_t *)buffer) = htons(length);

                printf(" [NO NS] Fail to match the domain!\n");
                printf("****************************************\n");
            }
            // Send the packet.
            tcp_send(client_sock, buffer, length + 2);
            // Release memory.
            free(header);
            free_query(query);
            break;
        }
        close(client_sock);
    }
    free_records(records, count);
    close(sock);
}