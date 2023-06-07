#include "data.h"
#include "dns.h"
#include "include/dns.h"
#include "records.h"
#include "socket.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    struct sockaddr_in client_addr;
    init_receiver_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in local_server_addr;
    init_receiver_addr(&local_server_addr, LOCAL_SERVER_IP);

    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "-h"))) {
        printf("Usage: ./client <domain> <type>\n");
        exit(1);
    }
    if (argc != 3) {
        printf("Invalid input!\n");
        exit(1);
    }
    char *domain = argv[1];
    char *type = argv[2];
    char buffer[BUFSIZE] = {0};

    dns_header *header = (dns_header *)malloc(sizeof(dns_header));
    dns_query *query = (dns_query *)malloc(sizeof(dns_query));
    if (get_type(type) != PTR)
        init_header(header, generate_random_id(),
                    generate_flags(QR_REQURST, OP_STD, 0, R_FINE), 1, 0, 0, 0);
    else
        init_header(header, generate_random_id(),
                    generate_flags(QR_REQURST, OP_INV, 0, R_FINE), 1, 0, 0, 0);
    init_query(query, domain, get_type(type));
    if (get_type(type) == PTR) {
        char rdomain[DOMAIN_MAX_LENGTH] = {0};
        serialize_ptr(rdomain, query->domain);
        query->domain = malloc(strlen(rdomain) + 1);
        strcpy(query->domain, rdomain);
    }

    uint16_t length = 0;
    length += add_header(buffer, header);
    length += add_query(buffer + length, query);

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    int sock = udp_socket();
    udp_send(sock, &local_server_addr, buffer, length);
    memset(buffer, 0, BUFSIZE);
    udp_receive(sock, &client_addr, buffer);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double us = (end_time.tv_sec - start_time.tv_sec) +
                (end_time.tv_nsec - start_time.tv_nsec) / 1e3;

    length = 0;
    length += parse_header(header, buffer);
    length += parse_query(query, buffer + length);

    printf("\n************* DNS Response *************\n");
    dns_rr *rr = (dns_rr *)malloc(sizeof(dns_rr));

    if ((header->flags & 0xF) == R_NAME_ERROR) {
        printf(" > Not found!\n");
    } else {
        parse_rr(rr, buffer + length);
        printf(" > Result:\t %s\n", rr->data);
    }

    printf(" > Total time:\t %.2f us\n", us);
    printf("****************************************\n");

    free(header);
    free_query(query);
    free_rr(rr);
    close(sock);
}
