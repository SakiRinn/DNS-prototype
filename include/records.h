/**
 * @file records.h
 * @brief File I/O, and methods for the RR array.
 */
#ifndef RECORDS_H
#define RECORDS_H

#include "data.h"
#include <stdio.h>

// All the IP used in this project.
#define CLIENT_IP "127.0.0.1"
#define LOCAL_SERVER_IP "127.0.0.2"
#define ROOT_SERVER_IP "127.0.1.1"
#define COMORG_SERVER_IP "127.1.1.1"
#define CNUS_SERVER_IP "127.1.1.2"
#define PTR_SERVER_IP "127.1.1.3"
#define EDU_SERVER_IP "127.1.2.1"
#define GOV_SERVER_IP "127.1.2.2"

/**
 * @brief Load records from a file.
 * @param records * The pointer to the records to be loaded into
 * @param path The path to the file
 * @return The number of records or -1 if failed
 */
ssize_t load_records(dns_rr *records[], const char path[]);
/**
 * @brief Find NS record in an array of records that matches the query.
 * @param records The array of records
 * @param count The number of records
 * @param query The query to match
 * @return The index of record or - 1 if not exists
 */
int find_ns_by_query(dns_rr records[], int count, dns_query *query);
/**
 * @brief Find a record in an array of records.
 * @param records The array of records
 * @param count The number of records
 * @param domain The domain to search for
 * @param type The type to search for
 * @return The index of record or - 1 if not exists
 */
int find_rr(dns_rr records[], int count, const char domain[], uint16_t type);
/**
 * @brief Free an array of records.
 * @param records The array of records
 * @param count The number of records
 */
void free_records(dns_rr records[], int count);
/**
 * @brief Save a DNS record to a file
 * @param rr The record to be saved
 * @param path The path to the file
 */
void save_rr(dns_rr rr, const char path[]);

#endif