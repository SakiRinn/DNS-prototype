#include "client.h"
#include "dns.h"
#include "server.h"
#include "socket.h"

int main() {
    struct sockaddr_in client_addr;
    init_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in local_server_addr;
    init_addr(&local_server_addr, LOCAL_SERVER_IP);

    int sock = udp_socket();
    // if (connect(sock, (struct sockaddr *)&localserver_addr,
    //             sizeof(localserver_addr)) < 1) {
    //     perror("connect failed");
    //     close(sock);
    // }
    char qname[127] = {0};
    char qtype[127] = {0};

    char packetOut[BUFSIZE] = {0};
    char packetIn[BUFSIZE] = {0};
    // memset(packetOut, 0, sizeof(packetOut));
    // memset(packetIn, 0, sizeof(packetIn));

    printf("Input the domain:\n");
    scanf("%s %s", qname, qtype);

    unsigned short type = A;
    if (!strcmp(qtype, "A")) {
        type = A;
    }else if (!strcmp(qtype, "MX")) {
        type = MX;
    }else if (!strcmp(qtype, "CNAME")) {
        type = CNAME;
    }else if (!strcmp(qtype, "PTR")) {
        type = PTR;
    }else{
        printf("Invalid type!");
    }

    struct DNS_Header *header = malloc(sizeof(struct DNS_Header));
    struct DNS_Query *query = malloc(sizeof(struct DNS_Query));
    // memset(query, 0, strlen(qname)+5);
    gen_dns_header(header, FLAGS_QUERY, 1, 0);
    gen_dns_query(query, qname, type);
    int len = gen_client_query_packet(packetOut, header, query);

    udp_send(sock, &local_server_addr, packetOut, len);
    unsigned int sock_len = 0;

    udp_receive(sock, &client_addr, packetIn);

    struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
    parse_dns_response(packetIn, rr);
    printf("%s", rr->rdata);
    free(rr->rdata);
    free(rr);

    free(query->name);
    free(header);
    free(query);
    close(sock);
}
