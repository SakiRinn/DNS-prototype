#ifndef DNS_H
#define DNS_H

#include "data.h"
#include <netinet/in.h>

#define DNS_PORT 53
#define SENDER_PORT 54000

#define NAME_PTR 0xc0
#define DOMAIN_MAX_LEVEL 16
#define DOMAIN_MAX_LENGTH 128
#define ARRAY_CAPACITY 20

#define QR_REQURST 0
#define QR_RESPONSE 1

#define OP_STD 0
#define OP_INV 1

#define R_FINE 0
#define R_NAME_ERROR 3
#define R_TYPE_ERROR 4

#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define PTR 12

#define IN 1


uint16_t generate_random_id();
uint16_t generate_flags(uint8_t QR, uint8_t opcode, uint8_t AA, uint8_t rcode);

void split(char *strings[], char string[]);
uint32_t addr_to_binary(const char addr_string[]);
void addr_to_string(char *addr_string, uint32_t addr_binary);
void init_receiver_addr(struct sockaddr_in *sockaddr, const char *addr);
void init_sender_addr(struct sockaddr_in *sockaddr, const char *addr);
void serialize_addr(char *addr, char **rdata);

uint16_t get_type(const char type[]);
uint16_t get_class(const char class[]);

void parse_name(char domain[], const unsigned char rdomain[]);
void serialize_name(unsigned char rdomain[], const char domain[]);

void parse_ptr(char *ip, const char *data);
void serialize_ptr(char *data, const char *ip);


#endif