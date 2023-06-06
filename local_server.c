#include "dns.h"
#include "server.h"
#include "socket.h"
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main() {
    struct sockaddr_in client_addr;
    init_receiver_addr(&client_addr, CLIENT_IP);
    struct sockaddr_in recv_addr;
    init_receiver_addr(&recv_addr, LOCAL_SERVER_IP);
    struct sockaddr_in send_addr;
    init_sender_addr(&send_addr, LOCAL_SERVER_IP);
    struct sockaddr_in root_server_addr;
    init_receiver_addr(&root_server_addr, ROOT_SERVER_IP);

    int udp_sock = udp_socket();
    server_bind(udp_sock, &recv_addr);

    char packet[BUFSIZE] = {0};
    char query_packet[BUFSIZE] = {0};

    while (1) {
        memset(packet, 0, BUFSIZE);
        memset(query_packet, 0, BUFSIZE);
        udp_receive(udp_sock, &client_addr, query_packet);

        memcpy(packet, query_packet, BUFSIZE);
        struct DNS_Header *header = (struct DNS_Header *)packet;
        struct DNS_Query *query = malloc(sizeof(struct DNS_Query));

        int tcp_sock;
        short query_len = parse_query_packet(packet, header, query);
        short offset = query_len;
        char data[127] = {0};
        int len = 12;
        if (load_data(packet, query, &len, "local_server_cache.txt")) {
            printf("%s", query->name);
            header = (struct DNS_Header *)packet;
            header->flags = htons(FLAGS_RESPONSE);
            // gen_response_packet(packet, header, 1);

            udp_send(udp_sock, &client_addr, packet, len);
        } else if (ntohs(query->qtype) == PTR) {
            header->flags = htons(FLAGS_NOTFOUND);
            udp_send(udp_sock, &client_addr, packet, offset);
        } else {

            gen_tcp_packet(query_packet, offset);
            offset += 2;
            tcp_sock = tcp_socket();
            server_bind(tcp_sock, &send_addr);
            tcp_connect(tcp_sock, &root_server_addr);
            tcp_send(tcp_sock, query_packet, offset);

            while (1) {
                memset(packet, 0, BUFSIZE);
                offset = query_len + 2;
                tcp_receive(tcp_sock, packet);
                header = (struct DNS_Header *)(packet + 2);
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
                if (ntohs(header->flags) == FLAGS_NOTFOUND) {
                    close(tcp_sock);
                    int len = cal_packet_len(packet + 2);
                    gen_udp_packet(packet, len);
                    udp_send(udp_sock, &client_addr, packet, len);
                    free(rr);
                    break;
                }

                if (header->answerNum == 0) {
                    int num = ntohs(header->authorNum) + ntohs(header->addNum);

                    for (int i = 0; i < num; i++) {

                        offset += parse_rr(packet + offset, rr);
                    }
                    close(tcp_sock);
                    tcp_sock = tcp_socket();
                    server_bind(tcp_sock, &send_addr);
                    char ns_addr[16] = {0};
                    parse_addr(ns_addr, rr->rdata);
                    struct sockaddr_in ns = {0};
                    init_addr(&ns, ns_addr);
                    tcp_connect(tcp_sock, &ns);
                    tcp_send(tcp_sock, query_packet, query_len + 2);
                    free_rr(rr);

                } else {
                    close(tcp_sock);
                    int len = cal_packet_len(packet + 2);
                    gen_udp_packet(packet, len);
                    header = (struct DNS_Header *)packet;

                    add_local_cache(packet, query_len);
                    udp_send(udp_sock, &client_addr, packet, len);
                    free(rr);
                    break;
                }
            }
        }
    }

    close(udp_sock);
}