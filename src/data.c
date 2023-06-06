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
    header->num_authority_rr = num_addition_rr;
}

int parse_header(dns_header *header, uint8_t buffer[]) {
    int offset = 0;

    header->id = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->flags = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->num_query = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->num_answer_rr = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->num_authority_rr = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    header->num_addition_rr = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    return offset;
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

void init_query(dns_query *query, char *domain, uint16_t type) {
    query->domain = domain;
    query->type = type;
    query->class = IN;
}

int parse_query(dns_query *query, uint8_t buffer[]) {
    int offset = 0;

    unsigned char *rdomain[DOMAIN_MAX_LENGTH] = {0};
    strcpy(rdomain, buffer);
    query->domain = (uint8_t *)malloc(strlen(buffer) + 1);
    parse_name(rdomain, query->domain);
    offset += strlen(buffer) + 1;

    query->type = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);
    query->class = ntohs(*(uint16_t *)(buffer + offset));
    offset += sizeof(uint16_t);

    return offset;
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

    unsigned char *rdomain[DOMAIN_MAX_LENGTH] = {0};
    if (query->type == PTR)
        serialize_ptr(rdomain, query->domain);
    else
        serialize_name(rdomain, query->domain);
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

void init_rr(dns_rr *rr, uint16_t type, uint32_t ttl, char *addr, char offset,
             char *domain) {
    if (offset != 0) {
        rr->domain = malloc(2);
        rr->domain[0] = NAME_PTR;
        rr->domain[1] = offset;
    } else {
        rr->domain = malloc(strlen(domain) + 2);
        serialize_name(rr->domain, domain);
    }

    rr->class = htons(IN);
    rr->type = htons(type);
    rr->ttl = htonl(ttl);

    unsigned short len = 0;
    if (type == A) {
        len = 4;
        rr->data = malloc(len);
        serialize_addr(addr, &rr->data);
    } else if (type == MX) {
        len = strlen(addr) + 4;
        rr->data = malloc(len);

        serialize_name(rr->data + 2, addr);
    } else {
        len = strlen(addr) + 2;
        rr->data = malloc(len);
        serialize_name(rr->data, addr);
    }

    rr->length = htons(len);
}

ssize_t get_records(dns_rr *records[], const char *path) {
    FILE *f = fopen(path, "r");

    *records = (dns_rr *)malloc(ARRAY_CAPACITY * sizeof(dns_rr));
    memset(*records, 0, ARRAY_CAPACITY * sizeof(dns_rr));

    int count = -1;
    for (count = 0; !feof(f); count++) {
        dns_rr *rr = *records + count;
        char class[8] = {0};
        char type[8] = {0};
        rr->domain = (uint8_t *)malloc(DOMAIN_MAX_LENGTH);
        rr->data = (uint8_t *)malloc(DOMAIN_MAX_LENGTH);

        memset(rr->domain, 0, DOMAIN_MAX_LENGTH);
        fscanf(f, "%s %d %s %s %s\n", rr->domain, &rr->ttl, class, type,
               rr->data);
        rr->domain = (uint8_t *)realloc(rr->domain, (strlen(rr->domain) + 1));
        rr->data = (uint8_t *)realloc(rr->data, (strlen(rr->data) + 1));
        rr->length = strlen(rr->data) + 2;
        rr->type = get_type(type);
        rr->class = get_class(class);

        if ((count + 1) % ARRAY_CAPACITY == 0) {
            *records = (dns_rr *)realloc(*records, (count + ARRAY_CAPACITY) *
                                                       sizeof(dns_rr));
            memset(records + count + 1, 0, ARRAY_CAPACITY * sizeof(dns_rr));
        }
    }
    fclose(f);
    return count;
}

int find_ns(dns_rr records[], int count, dns_query *query) {
    for (int i = 0; i < count; i++) {
        if (records[i].type == NS && strstr(query->domain, records[i].domain))
            return i;
    }
    return -1;
}

int find_a_for_ns(dns_rr records[], int count, const char *ns_domain) {
    for (int i = 0; i < count; i++) {
        if (records[i].type == A && !strcmp(records[i].domain, ns_domain))
            return i;
    }
    return -1;
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

    unsigned char *rdomain[DOMAIN_MAX_LENGTH] = {0};
    serialize_name(rdomain, rr->domain);
    strcpy(buffer, rdomain);
    size += strlen(rdomain) + 1;

    hton_rr(rr);
    memcpy(buffer + size, (uint8_t *)rr + sizeof(uint8_t *),
           sizeof(struct DNS_RR) - 2 * sizeof(uint8_t *));
    ntoh_rr(rr);
    size += sizeof(struct DNS_RR) - 2 * sizeof(uint8_t *);

    memset(rdomain, 0, DOMAIN_MAX_LENGTH);
    serialize_name(rdomain, rr->data);
    strcpy(buffer + size, rdomain);
    size += strlen(rdomain) + 1;

    return size;
}

int add_ip_rr(uint8_t buffer[], dns_rr *rr) {
    int size = 0;

    unsigned char *rdomain[DOMAIN_MAX_LENGTH] = {0};
    serialize_name(rdomain, rr->domain);
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