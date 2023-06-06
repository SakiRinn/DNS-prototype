#include "server.h"
#include "dns.h"
#include "socket.h"
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

void gen_tcp_packet(char *packet, int len) {
    char tmp[BUFSIZE] = {0};
    unsigned int nlen = htons(len);
    memcpy(tmp, packet, len);
    memcpy(packet, &nlen, 2);
    memcpy(packet + 2, tmp, len);
}

void gen_udp_packet(char *packet, int len) {
    char tmp[BUFSIZE] = {0};
    memcpy(tmp, packet + 2, len);
    memset(packet, 0, len + 2);
    memcpy(packet, tmp, len);
}

void update_packet_len(char *packet) {
    u_int16_t len = cal_packet_len(packet + 2);
    memcpy(packet, &len, 2);
}

void get_root_name(char *name, char *root) {

    int i = 0;
    char tmp[16];
    while (name[i] != '\0') {
        memset(tmp, 0, 16);
        memcpy(tmp, name + i + 1, name[i]);
        i += (name[i] + 1);
    }
    strcpy(root, tmp);
}

void get_second_name(char *rname, char *name) {
    int i = 0;
    int idx[10] = {0};
    int count = 0;
    while (name[i] != '\0') {
        idx[count] = i;
        i += (name[i] + 1);
        count++;
    }
    int start = idx[count - 2];
    memcpy(name, rname + start + 1, rname[start]);
}

void get_third_name(char *rname, char *name) {
    int i = 0;
    int idx[10] = {0};
    int count = 0;
    while (name[i] != '\0') {
        idx[count] = i;
        i += (name[i] + 1);
        count++;
    }
    int start = idx[count - 3];
    memcpy(name, rname + start + 1, rname[start]);
}

int get_local_cache(char *packet, struct DNS_Query *query, short offset) {
    FILE *fp = fopen("./data/local_server_cache.txt", "r");
    int ret = 0;
    if (fp == NULL) {
        perror("file open failed");
        return 0;
    }
    int flag = 0;
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_domain(query->name, rname);
    }

    char rr_offset = sizeof(struct DNS_Header);
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type || ntype == A) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));

                if (flag) {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                } else {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                }
                gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                offset += add_rr(packet + offset, rr);
                if (ntype == PTR) {

                    free(rr);
                    return 1;
                } else if (ntype == MX) {

                    flag = 1;
                    rr_offset += (14 + strlen(rdata) + 1);
                    bzero(rname, 128);
                    strcpy(rname, rdata);

                } else {
                    rr_offset += (12 + strlen(rdata) + 1);
                    ret = 1;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return ret;
}

int load_data(char *packet, struct DNS_Query *query, short *offset,
              const char *file) {
    char file_name[32] = "./data/";
    strcat(file_name, file);
    FILE *fp = fopen(file_name, "r");
    if (fp == NULL) {
        perror("file open failed");
        return 0;
    }
    int ret = 0;
    int flag = 0;
    struct DNS_Header *header = (struct DNS_Header *)packet;
    short type = ntohs(query->qtype);
    char rname[128] = {0};
    if (ntohs(query->qtype) == PTR) {
        parse_ptr(query->name, rname);
    } else {
        parse_domain(query->name, rname);
    }

    char rr_offset = sizeof(struct DNS_Header);
    while (!feof(fp)) {

        char name[128] = {0};
        int ttl;
        char rclass[3] = {0};
        char rtype[6] = {0};
        char rdata[128] = {0};
        fscanf(fp, "%s %d %s %s %s\n", name, &ttl, rclass, rtype, rdata);
        if (!strcmp(rname, name)) {
            int ntype = get_type(rtype);
            if (ntype == type || ntype == A) {
                struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));

                gen_dns_rr(rr, ntype, ttl, rdata, rr_offset, name);
                *offset += add_rr(packet + *offset, rr);
                if (ntype == PTR) {
                    header->addNum = htons(ntohs(header->addNum) + 1);
                    free(rr);
                    return 1;
                } else if (ntype == MX) {
                    header->answerNum = htons(ntohs(header->answerNum) + 1);
                    flag = 1;
                    rr_offset += (14 + strlen(rdata) + 1);
                    bzero(rname, 128);
                    strcpy(rname, rdata);

                } else if (ntype == NS) {
                    header->authorNum = htons(ntohs(header->authorNum) + 1);
                    flag = 1;
                    rr_offset += (12 + strlen(rdata) + 1);
                    bzero(rname, 128);
                    strcpy(rname, rdata);
                } else {
                    if (flag) {
                        header->addNum = htons(ntohs(header->addNum) + 1);
                    } else {
                        header->answerNum = htons(ntohs(header->answerNum) + 1);
                    }
                    rr_offset += (12 + strlen(rdata) + 1);
                    ret = 1;
                }

                free(rr);
            }
        }
    }
    fclose(fp);
    return ret;
}

void add_local_cache(char *packet, int ans_num) {

    FILE *fp = fopen("./data/local_server_cache.txt", "a");
    if (fp == NULL) {
        perror("file open failed");
        return;
    }
    int offset = 0;
    for (int i = 0; i < ans_num; i++) {
        struct DNS_RR *rr = malloc(sizeof(struct DNS_RR));
        offset += parse_rr(packet + offset, rr);
        char name[128] = {0};
        char rdata[128] = {0};
        int ttl = ntohl(rr->ttl);
        char *rclass = "IN";
        char rtype[6] = {0};
        get_type_name(ntohs(rr->type), rtype);
        if (ntohs(rr->type) == PTR) {
            parse_ptr(rr->domain, name);
            parse_domain(rr->rdata, rdata);
        }

        else {
            parse_domain(rr->domain, name);
            if (ntohs(rr->type) == A)
                addr_to_text(rdata, rr->rdata);
            else
                parse_domain(rr->rdata, rdata);
        }
        fprintf(fp, "%s %d %s %s %s\n", name, ttl, rclass, rtype, rdata);
    }
    fclose(fp);
}