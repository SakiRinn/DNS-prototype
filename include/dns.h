/**
 * @file dns.h
 * @brief Some utility functions for DNS.
 */
#ifndef DNS_H
#define DNS_H

#include "data.h"
#include <netinet/in.h>

#define DNS_PORT 53
#define SENDER_PORT 50000

#define DOMAIN_MAX_LEVEL 16
#define DOMAIN_MAX_LENGTH 128
#define ARRAY_CAPACITY 20

// QR bit macro
#define QR_REQURST 0
#define QR_RESPONSE 1

// OPCODE macro
#define OP_STD 0
#define OP_INV 1

// RCODE macro
#define R_FINE 0
#define R_NAME_ERROR 3

// Type macro
#define A 1
#define NS 2
#define CNAME 5
#define MX 15
#define PTR 12

// Class macro
#define IN 1

/**
 * @brief Generate a random transaction ID.
 * @return A transaction ID
 */
uint16_t generate_random_id();
/**
 * @brief Generate flags of DNS header.
 * @param QR 1 bit of QR
 * @param opcode 4 bits of OPCODE
 * @param AA 1 bit of AA
 * @param rcode 4 bits of RCODE
 * @return 16 bits of flags
 */
uint16_t generate_flags(uint8_t QR, uint8_t opcode, uint8_t AA, uint8_t rcode);

/**
 * @brief Splits a string into an array of strings by dot.
 * @param strings The array to store the output strings
 * @param string The input string
 */
void split(char *strings[], char string[]);

/**
 * @brief Convert an IPv4 address to binary.
 * @param addr_string The IPv4 address to convert
 * @return The binary representation of the input address
 */
uint32_t addr_to_binary(const char addr_string[]);
/**
 * @brief Convert an IPv4 address to a string.
 * @param addr_string The string to fill with the output address string
 * @param addr_binary The binary IPv4 address to be converted
 */
void addr_to_string(char addr_string[], uint32_t addr_binary);
/**
 * @brief Initialize the receiver's address. (Port 53)
 * @param sockaddr * pointer to the struct sockaddr_in to be initialized
 * @param addr The IPv4 address
 */
void init_receiver_addr(struct sockaddr_in *sockaddr, const char addr[]);
/**
 * @brief Initialize the sender's address. (High port)
 * @param sockaddr * pointer to the struct sockaddr_in to be initialized
 * @param addr The IPv4 address
 */
void init_sender_addr(struct sockaddr_in *sockaddr, const char addr[]);

/**
 * @brief Get type macro from string.
 * @param type String to look up
 * @return The type or 0 if not found
 */
uint16_t get_type(const char type[]);
/**
 * @brief Convert a type macro to a string.
 * @param type The type macro
 * @return The corresponding string
 */
const char *type_to_string(uint16_t type);
/**
 * @brief Get class macro from string.
 * @param class String to look up
 * @return The class or 0 if not found
 */
uint16_t get_class(const char class[]);
/**
 * @brief Convert a class macro to a string.
 * @param class The class macro
 * @return The corresponding string
 */
const char *class_to_string(uint16_t class);

/**
 * @brief Replaces the number of characters in the single-level domain in an IP
 * address with dots.
 * @param domain The domain of dot format
 * @param rdomain The domain of number format
 */
void parse_domain(char domain[], const unsigned char rdomain[]);
/**
 * @brief Replaces dots in an IP address with the number of characters in the
 * single-level domain.
 * @param rdomain The domain of number format
 * @param domain The domain of dot format
 */
void serialize_domain(unsigned char rdomain[], const char domain[]);

/**
 * @brief Convert an IP address of PTR to an IPv4 address.
 * @param ip The IPv4 address
 * @param rdomain The IP address of PTR
 */
void parse_ptr(char ip[], const unsigned char rdomain[]);
/**
 * @brief Convert an IPv4 address to an IP address of PTR.
 * @param rdomain The IP address of PTR
 * @param ip The IPv4 address
 */
void serialize_ptr(unsigned char rdomain[], const char ip[]);

#endif