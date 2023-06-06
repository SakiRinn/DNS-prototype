#include "client.h"
#include "data.h"
#include "dns.h"
#include "include/dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <stdint.h>

int main() {
    struct sockaddr_in client_addr;
    struct sockaddr_in local_server_addr;
    init_receiver_addr(&client_addr, CLIENT_IP);
    init_receiver_addr(&local_server_addr, LOCAL_SERVER_IP);

    int sock = udp_socket();
    char domain[DOMAIN_MAX_LENGTH] = {0};
    char type[16] = {0};

    char buffer_in[BUFSIZE] = {0};
    char buffer_out[BUFSIZE] = {0};

    printf("Input the domain:\n");
    scanf("%s %s", domain, type);

    dns_header *header = (dns_header *)malloc(sizeof(dns_header));
    dns_query *query = (dns_query *)malloc(sizeof(dns_query));

    init_header(header, generate_random_id(),
                generate_flags(QR_REQURST, OP_STD, 0, R_FINE), 1, 0, 0, 0);
    hton_header(header);
    init_query(query, domain, get_type(type));
    hton_query(query);

    unsigned short length = 0;
    length += add_header(buffer_out + 2, header);
    length += add_query(buffer_out + 2 + length, query);
    *((unsigned short *)buffer_out) = htons(length);

    free(header);
    free_query(query);

    udp_send(sock, &local_server_addr, buffer_out, length + 2);
    udp_receive(sock, &client_addr, buffer_in);

    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    header = (struct DNS_Header *)buffer_in;
    printf("DNS Response\n");
    if (ntohs(header->flags) == FLAGS_NOTFOUND) {
        printf("Not found!\n");
    } else {
        parse_dns_response(buffer_in, rr);

        printf("Address: %s\n", rr->data);
        free(rr->data);
    }
    free(rr);

    close(sock);
}
