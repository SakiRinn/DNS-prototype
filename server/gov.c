#include "data.h"
#include "dns.h"
#include "records.h"
#include "socket.h"
#include <string.h>

int main() {
    // Init address.
    struct sockaddr_in local_server_addr;
    struct sockaddr_in gov_addr;
    init_receiver_addr(&gov_addr, GOV_SERVER_IP);

    // Create TCP socket and set to the listen mode.
    int sock = tcp_socket();
    set_socket_reuse(sock);
    server_bind(sock, &gov_addr);
    tcp_listen(sock);

    // Load data.
    dns_rr *records;
    int count = load_records(&records, "./data/gov.txt");

    while (1) {
        // Accept a new connection.
        int client_sock = tcp_accept(sock, &local_server_addr);
        set_socket_reuse(client_sock);
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
            int idx = find_rr(records, count, query->domain, query->type);
            if (idx != -1) {
                // If found ?
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_STD, 0, R_FINE),
                            header->num_query, 1, 0, query->type == MX ? 1 : 0);
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);

                int a_idx = 0;
                if (query->type == A)
                    length += add_ip_rr(buffer + 2 + length, records + idx);
                else if (query->type == MX) {
                    length += add_domain_rr(buffer + 2 + length, records + idx);
                    a_idx = find_rr(records, count, records[idx].data, A);
                    if (a_idx == -1) {
                        perror("Database error");
                        exit(EXIT_FAILURE);
                    }
                    length += add_ip_rr(buffer + 2 + length, records + a_idx);
                } else
                    length += add_domain_rr(buffer + 2 + length, records + idx);

                *((uint16_t *)buffer) = htons(length);

                printf(" > Result: \t%s\n", records[idx].data);
                if (query->type == MX)
                    printf(" > MX IP: \t%s\n", records[a_idx].data);
                printf("****************************************\n");
            } else {
                // If not found ?
                init_header(
                    header, header->id,
                    generate_flags(QR_RESPONSE, OP_STD, 0, R_NAME_ERROR),
                    header->num_query, 0, 0, 0);
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((uint16_t *)buffer) = htons(length);
                printf(" [NO Result] Fail to match the domain!\n");
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