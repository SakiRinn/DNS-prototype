#ifndef DATA_H
#define DATA_H

#include <stdint.h>
#include <stdio.h>

#pragma pack(push, 1)

typedef struct DNS_Header {
    uint16_t id;
    uint16_t flags;
    uint16_t num_query;
    uint16_t num_answer_rr;
    uint16_t num_authority_rr;
    uint16_t num_addition_rr;
} dns_header;

typedef struct DNS_Query {
    char *domain;
    uint16_t type;
    uint16_t class;
} dns_query;

typedef struct DNS_RR {
    char *domain;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    char *data;
} dns_rr;

#pragma pack(pop)

void init_header(dns_header *header, uint16_t id, uint16_t flags,
                 uint16_t num_query, uint16_t num_answer_rr,
                 uint16_t num_authority_rr, uint16_t num_addition_rr);
int parse_header(dns_header *header, uint8_t buffer[]);
void hton_header(dns_header *header);
void ntoh_header(dns_header *header);
int add_header(uint8_t buffer[], dns_header *header);

void init_query(dns_query *query, char domain[], uint16_t type);
int parse_query(dns_query *query, uint8_t buffer[]);
void hton_query(dns_query *query);
void ntoh_query(dns_query *query);
int add_query(uint8_t buffer[], dns_query *query);
void free_query(dns_query *query);

void init_rr(dns_rr *rr, char domain[], uint16_t type, uint32_t ttl,
             char data[]);
int parse_rr(dns_rr *rr, uint8_t buffer[]);
void hton_rr(dns_rr *rr);
void ntoh_rr(dns_rr *rr);
int add_domain_rr(uint8_t buffer[], dns_rr *rr);
int add_ip_rr(uint8_t buffer[], dns_rr *rr);
void free_rr(dns_rr *rr);

#endif