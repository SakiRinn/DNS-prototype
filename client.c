#include "data.h"
#include "dns.h"
#include "include/dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    struct sockaddr_in client_addr;
    struct sockaddr_in local_server_addr;
    init_receiver_addr(&client_addr, CLIENT_IP);
    init_receiver_addr(&local_server_addr, LOCAL_SERVER_IP);

    if (argc == 1 || (argc == 2 && !strcmp(argv[1], "-h"))) {
        printf("Usage: ./client domain type\n");
        exit(1);
    }
    if (argc != 3) {
        printf("Wrong argument number!\n");
        exit(1);
    }
    char *domain = argv[1];
    char *type = argv[2];
    char buffer[BUFSIZE] = {0};

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    int sock = udp_socket();

    dns_header *header = (dns_header *)malloc(sizeof(dns_header));
    dns_query *query = (dns_query *)malloc(sizeof(dns_query));
    if (get_type(type) != PTR)
        init_header(header, generate_random_id(),
                    generate_flags(QR_REQURST, OP_STD, 0, R_FINE), 1, 0, 0, 0);
    else
        init_header(header, generate_random_id(),
                    generate_flags(QR_REQURST, OP_INV, 0, R_FINE), 1, 0, 0, 0);
    init_query(query, domain, get_type(type));

    unsigned short length = 0;
    length += add_header(buffer, header);
    length += add_query(buffer + length, query);

    udp_send(sock, &local_server_addr, buffer, length);
    memset(buffer, 0, BUFSIZE);

    udp_receive(sock, &client_addr, buffer);
    length = 0;
    length += parse_header(header, buffer);
    length += parse_query(query, buffer + length);

    dns_rr *rr = (dns_rr *)malloc(sizeof(dns_rr));

    printf("********** DNS Response **********\n");
    if ((header->flags % 0xF == R_NAME_ERROR)) {
        printf("* Not found!\n");
    } else {
        parse_rr(rr, buffer + length);
        printf("* Address:\t %s\n", rr->data);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double ms = (end_time.tv_sec - start_time.tv_sec) * 1e3 +
                (end_time.tv_nsec - start_time.tv_nsec) / 1e6;
    printf("* Total time:\t %.2fms\n", ms);
    printf("**********************************\n");

    free(header);
    free_query(query);
    free_rr(rr);
    close(sock);
}
