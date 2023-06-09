#include "records.h"
#include "data.h"
#include "dns.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ssize_t load_records(dns_rr *records[], const char path[]) {
    // Open the file.
    FILE *f = fopen(path, "r");

    // Allocate the record array.
    *records = (dns_rr *)malloc(ARRAY_CAPACITY * sizeof(dns_rr));
    memset(*records, 0, ARRAY_CAPACITY * sizeof(dns_rr));

    int count = -1;
    // Generate DNS records for each record in the file.
    for (count = 0; !feof(f); count++) {
        dns_rr *rr = *records + count;
        char class[8] = {0};
        char type[8] = {0};
        rr->domain = (char *)malloc(DOMAIN_MAX_LENGTH);
        rr->data = (char *)malloc(DOMAIN_MAX_LENGTH);

        memset(rr->domain, 0, DOMAIN_MAX_LENGTH);
        fscanf(f, "%s %d %s %s %s\n", rr->domain, &rr->ttl, class, type,
               rr->data);
        rr->domain = (char *)realloc(rr->domain, (strlen(rr->domain) + 1));
        rr->data = (char *)realloc(rr->data, (strlen(rr->data) + 1));
        rr->type = get_type(type);
        rr->class = get_class(class);
        rr->length =
            (rr->type == MX) ? strlen(rr->data) + 4 : strlen(rr->data) + 2;

        // If the array is too small, expand it.
        if ((count + 1) % ARRAY_CAPACITY == 0) {
            *records = (dns_rr *)realloc(*records, (count + ARRAY_CAPACITY) *
                                                       sizeof(dns_rr));
            memset(records + count + 1, 0, ARRAY_CAPACITY * sizeof(dns_rr));
        }
    }
    // Close the file.
    fclose(f);
    return count;
}

int find_ns_by_query(dns_rr records[], int count, dns_query *query) {
    for (int i = 0; i < count; i++) {
        // Returns the index of the matched record.
        if (records[i].type == NS &&
            strstr(query->type == PTR ? "in-addr.arpa" : query->domain,
                   records[i].domain))
            return i;
    }
    // If failed, -1 will be returned.
    return -1;
}

int find_rr(dns_rr records[], int count, const char domain[], uint16_t type) {
    for (int i = 0; i < count; i++) {
        // Returns the index of the matched record.
        if (records[i].type == type && !strcmp(records[i].domain, domain))
            return i;
    }
    // If failed, -1 will be returned.
    return -1;
}

void free_records(dns_rr records[], int count) {
    for (int i = 0; i < count; i++) {
        free(records[i].domain);
        free(records[i].data);
    }
    free(records);
}

void save_rr(dns_rr rr, const char path[]) {
    FILE *f = fopen(path, "a");
    // Exit with exit code EXIT_FAILURE.
    if (f == NULL)
        exit(EXIT_FAILURE);
    fseek(f, 0, SEEK_END);
    fprintf(f, "%s %u %s %s %s\n", rr.domain, rr.ttl, class_to_string(rr.class),
            type_to_string(rr.type), rr.data);
    fclose(f);
}