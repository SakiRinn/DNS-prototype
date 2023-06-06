#ifndef RECORDS_H
#define RECORDS_H

#include "data.h"
#include <stdio.h>

#define CLIENT_IP "127.0.0.1"
#define LOCAL_SERVER_IP "127.0.0.10"
#define ROOT_SERVER_IP "127.0.1.1"
#define COMORG_SERVER_IP "127.1.1.1"
#define CNUS_SERVER_IP "127.1.1.2"
#define SCD1_SERVER_IP "127.1.2.1"
#define SCD2_SERVER_IP "127.1.2.2"

ssize_t load_records(dns_rr *records[], const char path[]);
int find_ns_by_query(dns_rr records[], int count, dns_query *query);
int find_a_by_domain(dns_rr records[], int count, const char domain[]);
int find_rr(dns_rr records[], int count, const char domain[], uint16_t type);
void free_records(dns_rr records[], int count);
void save_rr(dns_rr rr, const char path[]);

#endif