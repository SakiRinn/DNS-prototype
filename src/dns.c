#include "dns.h"
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

uint16_t generate_random_id() {
    srand(time(NULL));
    return (uint16_t)rand();
}

uint16_t generate_flags(uint8_t QR, uint8_t opcode, uint8_t AA, uint8_t rcode) {
    if ((QR != 0 && QR != 1) || (AA != 0 && AA != 1))
        perror("QR or AA must be 1 byte! (only 0/1 supported)");
    return ((uint16_t)QR << 15) + ((uint16_t)opcode << 11) +
           ((uint16_t)AA << 10) + (uint16_t)rcode;
}

void split(char *strings[], char string[]) {
    strings[0] = string;
    int j = 1;
    unsigned long len = strlen(string);
    for (int i = 0; i < len; i++) {
        if (string[i] == '.') {
            string[i] = '\0';
            strings[j] = string + (i + 1);
            j++;
        }
    }
}

uint32_t addr_to_binary(const char addr_string[]) {
    char *addr = (char *)malloc(strlen(addr_string) + 1);
    strcpy(addr, addr_string);
    char *strings[4];
    split(strings, addr);

    unsigned int addr_binary = 0;
    for (int i = 0; i < 4; i++) {
        addr_binary += (unsigned int)atoi(strings[i]) << 8 * (3 - i);
    }
    return addr_binary;
}

void addr_to_string(char addr_string[], uint32_t addr_binary) {
    struct in_addr a;
    memset(&a, 0, sizeof(struct in_addr));
    a.s_addr = addr_binary;
    char *tmp = inet_ntoa(a);
    memcpy(addr_string, tmp, strlen(tmp));
}

void init_receiver_addr(struct sockaddr_in *sockaddr, const char addr[]) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(addr);
    sockaddr->sin_port = htons(DNS_PORT);
}

void init_sender_addr(struct sockaddr_in *sockaddr, const char addr[]) {
    memset(sockaddr, 0, sizeof(struct sockaddr_in));
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_addr.s_addr = inet_addr(addr);
    sockaddr->sin_port = htons(SENDER_PORT);
}

uint16_t get_type(const char type[]) {
    if (!strcmp("A", type))
        return A;
    else if (!strcmp("NS", type))
        return NS;
    else if (!strcmp("CNAME", type))
        return CNAME;
    else if (!strcmp("MX", type))
        return MX;
    else if (!strcmp("PTR", type))
        return PTR;
    else
        return 0;
}

uint16_t get_class(const char class[]) {
    if (!strcmp("IN", class))
        return IN;
    else
        return 0;
}

void parse_domain(char domain[], const unsigned char rdomain[]) {
    int i = 0;
    while (rdomain[i] != '\0') {
        memcpy(domain + i, rdomain + i + 1, rdomain[i]);
        i += (rdomain[i] + 1);
        domain[i - 1] = '.';
    }
    domain[i - 1] = '\0';
}

void serialize_domain(unsigned char rdomain[], const char domain[]) {
    int len = strlen(domain) + 1;
    memcpy(rdomain + 1, domain, len);
    int m = 0;
    char count = 0;
    for (int i = 0; i < len; i++) {
        if (domain[i] == '.') {
            rdomain[m] = count;
            m += (count + 1);
            count = 0;
        } else {
            count++;
        }
    }
    rdomain[m] = --count;
}

void parse_ptr(char ip[], const unsigned char rdomain[]) {
    int i = 0;
    char tmp[128];
    for (int j = 0; j < 4; j++) {
        memcpy(tmp + i, rdomain + i + 1, rdomain[i]);
        i += (rdomain[i] + 1);
        tmp[i - 1] = '.';
    }
    tmp[i - 1] = '\0';
    int len = strlen(tmp);
    for (int j = 0; j < len; j++) {
        ip[j] = tmp[len - j - 1];
    }
}

void serialize_ptr(unsigned char rdomain[], const char ip[]) {
    char tmp[128] = {0};
    strcpy(tmp, ip);
    int len = strlen(ip);

    for (int i = 0; i < len; i++) {
        tmp[i] = ip[len - i - 1];
    }
    strcat(tmp, ".in-addr.arpa");
    serialize_domain(rdomain, tmp);
}