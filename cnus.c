#include "client.h"
#include "data.h"
#include "dns.h"
#include "server.h"
#include "socket.h"
#include <string.h>

int main() {
    char qname[127] = {0};
    char qtype[127] = {0};
    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};

    struct sockaddr_in client_addr;
    struct sockaddr_in root_addr;
    init_receiver_addr(&root_addr, ROOT_SERVER_IP);

    int sock = tcp_socket();
    server_bind(sock, &root_addr);
    tcp_listen(sock);

    struct DNS_Header *header =
        (struct DNS_Header *)malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query =
        (struct DNS_Query *)malloc(sizeof(struct DNS_Query));

    while (1) {
        int client_sock = tcp_accept(sock, &client_addr);
        uint8_t buffer[BUFSIZE] = {0};

        ssize_t receive_len = 0;
        while (receive_len = tcp_receive(client_sock, buffer)) {
            int header_len = parse_header(buffer + 2, header);
            parse_query(buffer + 2 + header_len, query);

            memset(buffer, 0, BUFSIZE);
            struct DNS_RR *records;
            int cnt = get_records(&records, "./data/cnus.txt");
            unsigned short length = 0;

            int ns_idx = find_ns(records, cnt, query);
            if (ns_idx != -1) {
                init_header(header, header->id, 0x0000, header->num_query, 0, 1,
                            1);
                hton_header(header);
                int a_idx = find_a_for_ns(records, cnt, records[ns_idx].data);
                if (a_idx == -1) {
                    perror("Database error!");
                    exit(EXIT_FAILURE);
                }
                header->flags = htons(generate_flags(1, OP_STD, 1, R_FINE));
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                length += add_domain_rr(buffer + 2 + length, records + ns_idx);
                length += add_ip_rr(buffer + 2 + length, records + a_idx);
                *((unsigned short *)buffer) = htons(length);
            } else {
                init_header(header, header->id, 0x0000, header->num_query, 0, 0,
                            0);
                hton_header(header);
                header->flags =
                    htons(generate_flags(1, OP_STD, 1, R_NAME_ERROR));
                length += add_header(buffer + 2, header);
                length += add_query(buffer + 2 + length, query);
                *((unsigned short *)buffer) = htons(length);
            }
            tcp_send(client_sock, buffer, length + 2);
            break;
        }
        close(client_sock);
    }
    close(sock);
}