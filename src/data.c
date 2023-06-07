#include "data.h"
#include "dns.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void init_header(dns_header *header, uint16_t id, uint16_t flags,
                 uint16_t num_query, uint16_t num_answer_rr,
                 uint16_t num_authority_rr, uint16_t num_addition_rr) {
    header->id = id;
    header->flags = flags;
    header->num_query = num_query;
    header->num_answer_rr = num_answer_rr;
    header->num_authority_rr = num_authority_rr;
    header->num_addition_rr = num_addition_rr;
}

int parse_header(dns_header *header, uint8_t buffer[]) {
    int size = 0;

    header->id = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    header->flags = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    header->num_query = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    header->num_answer_rr = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    header->num_authority_rr = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    header->num_addition_rr = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);

    return size;
}

void hton_header(dns_header *header) {
    header->id = htons(header->id);
    header->flags = htons(header->flags);
    header->num_query = htons(header->num_query);
    header->num_answer_rr = htons(header->num_answer_rr);
    header->num_authority_rr = htons(header->num_authority_rr);
    header->num_addition_rr = htons(header->num_addition_rr);
}

void ntoh_header(dns_header *header) {
    header->id = ntohs(header->id);
    header->flags = ntohs(header->flags);
    header->num_query = ntohs(header->num_query);
    header->num_answer_rr = ntohs(header->num_answer_rr);
    header->num_authority_rr = ntohs(header->num_authority_rr);
    header->num_addition_rr = ntohs(header->num_addition_rr);
}

int add_header(uint8_t buffer[], dns_header *header) {
    int size = 0;

    hton_header(header);
    memcpy(buffer, header, sizeof(dns_header));
    ntoh_header(header);
    size += sizeof(struct DNS_Header);

    return size;
}

void init_query(dns_query *query, char domain[], uint16_t type) {
    query->domain = domain;
    query->type = type;
    query->class = IN;
}

int parse_query(dns_query *query, uint8_t buffer[]) {
    int size = 0;

    unsigned char rdomain[DOMAIN_MAX_LENGTH] = {0};
    strcpy(rdomain, buffer);
    query->domain = (uint8_t *)malloc(strlen(rdomain) + 1);
    parse_domain(query->domain, rdomain);
    size += strlen(rdomain) + 1;

    query->type = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    query->class = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);

    return size;
}

void hton_query(dns_query *query) {
    query->type = htons(query->type);
    query->class = htons(query->class);
}

void ntoh_query(dns_query *query) {
    query->type = ntohs(query->type);
    query->class = ntohs(query->class);
}

int add_query(uint8_t buffer[], dns_query *query) {
    int size = 0;

    unsigned char rdomain[DOMAIN_MAX_LENGTH] = {0};
    if (query->type == PTR)
        serialize_ptr(rdomain, query->domain);
    else
        serialize_domain(rdomain, query->domain);
    strcpy(buffer, rdomain);
    size += strlen(rdomain) + 1;

    hton_query(query);
    memcpy(buffer + size, (uint8_t *)query + sizeof(uint8_t *),
           sizeof(dns_query) - sizeof(uint8_t *));
    ntoh_query(query);
    size += sizeof(dns_query) - sizeof(uint8_t *);

    return size;
}

void free_query(dns_query *query) {
    free(query->domain);
    free(query);
}

void init_rr(dns_rr *rr, char domain[], uint16_t type, uint32_t ttl,
             char data[]) {
    rr->domain = domain;
    rr->type = type;
    rr->class = IN;
    rr->ttl = ttl;
    rr->length = strlen(data) + 1;
    rr->data = data;
}

int parse_rr(dns_rr *rr, uint8_t buffer[]) {
    int size = 0;

    unsigned char rdomain[DOMAIN_MAX_LENGTH] = {0};
    strcpy(rdomain, buffer);
    rr->domain = (char *)malloc(strlen(rdomain) + 1);
    parse_domain(rr->domain, rdomain);
    size += strlen(rdomain) + 1;

    rr->type = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    rr->class = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);
    rr->ttl = ntohl(*(uint32_t *)(buffer + size));
    size += sizeof(uint32_t);
    rr->length = ntohs(*(uint16_t *)(buffer + size));
    size += sizeof(uint16_t);

    if (rr->type == A) {
        char addr_string[DOMAIN_MAX_LENGTH];
        addr_to_string(addr_string, *(uint32_t *)(buffer + size));
        rr->data = (char *)malloc(strlen(addr_string) + 1);
        strcpy(rr->data, addr_string);
        size += 4;
    } else if (rr->type == MX) {
        memset(rdomain, 0, DOMAIN_MAX_LENGTH);
        strcpy(rdomain, buffer + size + 2);
        rr->data = (char *)malloc(strlen(rdomain) + 1);
        parse_domain(rr->data, rdomain);
        size += strlen(rdomain) + 3;
    } else {
        memset(rdomain, 0, DOMAIN_MAX_LENGTH);
        strcpy(rdomain, buffer + size);
        rr->data = (char *)malloc(strlen(rdomain) + 1);
        parse_domain(rr->data, rdomain);
        size += strlen(rdomain) + 1;
    }

    return size;
}

void hton_rr(dns_rr *rr) {
    rr->type = htons(rr->type);
    rr->class = htons(rr->class);
    rr->ttl = htonl(rr->ttl);
    rr->length = htons(rr->length);
}

void ntoh_rr(dns_rr *rr) {
    rr->type = ntohs(rr->type);
    rr->class = ntohs(rr->class);
    rr->ttl = ntohl(rr->ttl);
    rr->length = ntohs(rr->length);
}

int add_domain_rr(uint8_t buffer[], dns_rr *rr) {
    int size = 0;

    unsigned char rdomain[DOMAIN_MAX_LENGTH] = {0};
    serialize_domain(rdomain, rr->domain);
    strcpy(buffer, rdomain);
    size += strlen(rdomain) + 1;

    hton_rr(rr);
    memcpy(buffer + size, (uint8_t *)rr + sizeof(uint8_t *),
           sizeof(dns_rr) - 2 * sizeof(uint8_t *));
    ntoh_rr(rr);
    size += sizeof(dns_rr) - 2 * sizeof(uint8_t *);

    memset(rdomain, 0, DOMAIN_MAX_LENGTH);
    serialize_domain(rdomain, rr->data);
    if (rr->type == MX) {
        memset(buffer + size, 0, 2);
        size += 2;
    }
    strcpy(buffer + size, rdomain);
    size += strlen(rdomain) + 1;

    return size;
}

int add_ip_rr(uint8_t buffer[], dns_rr *rr) {
    int size = 0;

    unsigned char rdomain[DOMAIN_MAX_LENGTH] = {0};
    serialize_domain(rdomain, rr->domain);
    strcpy(buffer, rdomain);
    size += strlen(rdomain) + 1;

    rr->length = 4;
    hton_rr(rr);
    memcpy(buffer + size, (uint8_t *)rr + sizeof(uint8_t *),
           sizeof(dns_rr) - 2 * sizeof(uint8_t *));
    ntoh_rr(rr);
    size += sizeof(dns_rr) - 2 * sizeof(uint8_t *);

    unsigned int binary_ip = htonl(addr_to_binary(rr->data));
    memcpy(buffer + size, &binary_ip, 4);
    size += 4;

    return size;
}

void free_rr(dns_rr *rr) {
    free(rr->domain);
    free(rr->data);
    free(rr);
}