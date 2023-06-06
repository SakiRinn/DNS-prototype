#include "client.h"
#include "data.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <string.h>

int main() {
    struct sockaddr_in local_server_addr;
    struct sockaddr_in root_addr;
    init_receiver_addr(&root_addr, ROOT_SERVER_IP);

    int sock = tcp_socket();
    server_bind(sock, &root_addr);
    tcp_listen(sock);

    dns_rr *records;
    int count = get_records(&records, "./data/cnus.txt");

    while (1) {
        int client_sock = tcp_accept(sock, &local_server_addr);
        uint8_t buffer[BUFSIZE] = {0};

        dns_header *header = (dns_header *)malloc(sizeof(dns_header));
        dns_query *query = (dns_query *)malloc(sizeof(dns_query));

        int receive_len = 0;
        while (receive_len = tcp_receive(client_sock, buffer)) {
            int header_len = parse_header(buffer + 2, header);
            parse_query(query, buffer + 2 + header_len);
            memset(buffer, 0, BUFSIZE);

            unsigned short length = 0;
            int ns_idx = find_ns(records, count, query);
            if (ns_idx != -1) {
                init_header(header, header->id,
                            generate_flags(QR_RESPONSE, OP_STD, 1, R_FINE),
                            header->num_query, 0, 1, 1);
                int a_idx = find_a_for_ns(records, count, records[ns_idx].data);
                if (a_idx == -1) {
                    perror("Database error!");
                    exit(EXIT_FAILURE);
                }
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                length += add_domain_rr(buffer + 2 + length, records + ns_idx);
                length += add_ip_rr(buffer + 2 + length, records + a_idx);
                *((unsigned short *)buffer) = htons(length);
            } else {
                init_header(
                    header, header->id,
                    generate_flags(QR_RESPONSE, OP_STD, 1, R_NAME_ERROR),
                    header->num_query, 0, 0, 0);
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((unsigned short *)buffer) = htons(length);
            }
            free(header);
            free_query(query);
            tcp_send(client_sock, buffer, length + 2);
            break;
        }
        close(client_sock);
    }
    for (int i = 0; i < count; i++)
        free_rr(records + i);
    close(sock);
}