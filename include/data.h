/**
 * @file data.h
 * @brief The definition of data structures related to DNS, as well as the
 * methods for them.
 */
#ifndef DATA_H
#define DATA_H

#include <stdint.h>
#include <stdio.h>

// Set 1-byte alignment for every struct before pop.
#pragma pack(push, 1)

// The header of DNS packet
typedef struct DNS_Header {
    uint16_t id;
    uint16_t flags;
    uint16_t num_query;
    uint16_t num_answer_rr;
    uint16_t num_authority_rr;
    uint16_t num_addition_rr;
} dns_header;

// The DNS query
typedef struct DNS_Query {
    char *domain;
    uint16_t type;
    uint16_t class;
} dns_query;

// The DNS resource record (RR)
typedef struct DNS_RR {
    char *domain;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
    char *data;
} dns_rr;

#pragma pack(pop)

/**
 * @brief Initialize a DNS header.
 * @param header * The header to be initialized
 * @param id The transaction ID
 * @param flags The flags
 * @param num_query The number of queries in the record
 * @param num_answer_rr The number of answer RRs in the record
 * @param num_authority_rr The number of authority RRs in the record
 * @param num_addition_rr The number of addition RRs in the record
 */
void init_header(dns_header *header, uint16_t id, uint16_t flags,
                 uint16_t num_query, uint16_t num_answer_rr,
                 uint16_t num_authority_rr, uint16_t num_addition_rr);
/**
 * @brief Parse header and convert it to host byte order.
 * @param header * Pointer to the header to be filled
 * @param buffer Buffer to be parsed
 * @return The size of the header
 */
int parse_header(dns_header *header, uint8_t buffer[]);
/**
 * @brief Convert a header to network byte order.
 * @param header * Pointer to the header
 */
void hton_header(dns_header *header);
/**
 * @brief Convert a header to host byte order.
 * @param header * Pointer to the header
 */
void ntoh_header(dns_header *header);
/**
 * @brief Add a header to a buffer
 * @param buffer The output buffer
 * @param header * Pointer to the header to be added
 * @return Number of added bytes
 */
int add_header(uint8_t buffer[], dns_header *header);

/**
 * @brief Initialize a DNS query.
 * @param query * Pointer to the query to be initialized
 * @param domain The domain
 * @param type The type
 */
void init_query(dns_query *query, char domain[], uint16_t type);
/**
 * @brief Parse query and convert it to host byte order.
 * @param query * Pointer to the query to be filled
 * @param buffer Buffer to be parsed
 * @return The size of the query
 */
int parse_query(dns_query *query, uint8_t buffer[]);
/**
 * @brief Convert a query to host byte order.
 * @param query * Pointer to the query
 */
void hton_query(dns_query *query);
/**
 * @brief Add a query to a buffer
 * @param buffer The output buffer
 * @param query * Pointer to the query to be added
 * @return Number of added bytes
 */
void ntoh_query(dns_query *query);
/**
 * @brief Add a query to a buffer
 * @param buffer The output buffer
 * @param query * Pointer to the query to be added
 * @return Number of added bytes
 */
int add_query(uint8_t buffer[], dns_query *query);
/**
 * @brief Free a query.
 * @param query * pointer to the query
 */
void free_query(dns_query *query);

/**
 * @brief Initialize a DNS RR.
 * @param rr * Pointer to the RR to be initialized
 * @param domain The domain
 * @param type The type
 * @param ttl Time to live
 * @param data The data corresponding to the domain
 */
void init_rr(dns_rr *rr, char domain[], uint16_t type, uint32_t ttl,
             char data[]);
/**
 * @brief Parse RR and convert it to host byte order.
 * @param header * Pointer to the RR to be filled
 * @param buffer Buffer to be parsed
 * @return The size of the RR
 */
int parse_rr(dns_rr *rr, uint8_t buffer[]);
/**
 * @brief Convert a RR to host byte order.
 * @param rr * Pointer to the RR
 */
void hton_rr(dns_rr *rr);
/**
 * @brief Convert a RR to network byte order.
 * @param rr * Pointer to the RR
 */
void ntoh_rr(dns_rr *rr);
/**
 * @brief Add an RR to a buffer where the data of RR is stored as text.
 * @param buffer The output buffer
 * @param rr * Pointer to the RR to be added
 * @return Number of added bytes
 */
int add_domain_rr(uint8_t buffer[], dns_rr *rr);
/**
 * @brief Add an RR to a buffer where the data of RR is stored as binary.
 * @param buffer The output buffer
 * @param rr * Pointer to the RR to be added
 * @return Number of added bytes
 */
int add_ip_rr(uint8_t buffer[], dns_rr *rr);
/**
 * @brief Free a RR.
 * @param rr * pointer to the RR
 */
void free_rr(dns_rr *rr);

#endif