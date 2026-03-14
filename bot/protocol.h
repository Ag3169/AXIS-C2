#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include "includes.h"

/* ============================================================================
 * NETWORK PROTOCOL DEFINITIONS
 * ============================================================================
 * Ethernet types, IP protocols, TCP flags
 * Custom header structures to avoid system header conflicts
 * GRE, DNS, TCP/UDP header definitions
 * ============================================================================ */

/* Ethernet protocol types */
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806

/* IP protocol numbers */
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_GRE 47

/* TCP flags */
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/* TCP options */
#define TCP_OPT_MSS 2
#define TCP_OPT_SACK 4
#define TCP_OPT_TIMESTAMP 8
#define TCP_OPT_WSCALE 3

/* DNS */
#define PROTO_DNS 53

/* GRE */
#define PROTO_GRE_TRANS_ETH 0x6558
#define PROTO_GRE_TRANS_IP 0x0800

/* Custom IP header structure (to avoid system header conflicts) */
struct iphdr_custom {
    uint8_t version_ihl;  /* version (4 bits) + IHL (4 bits) */
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

/* Custom TCP header structure */
struct tcphdr_custom {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res_doff_flags;  /* reserved (4 bits) + doff (4 bits) + flags (8 bits) */
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

/* Helper macros for version/ihl */
#define IPHDR_SET_VERSION_IHL(v, i) (((v) << 4) | (i))
#define IPHDR_GET_VERSION(vihl) (((vihl) >> 4) & 0x0F)
#define IPHDR_GET_IHL(vihl) ((vihl) & 0x0F)

/* Helper macros for TCP doff/flags */
#define TCPHDR_SET_DOFF_FLAGS(d, f) (((d) << 12) | (f))
#define TCPHDR_GET_DOFF(df) (((df) >> 12) & 0x0F)
#define TCPHDR_GET_FLAGS(df) ((df) & 0x3F)

/* DNS header structure */
struct dnshdr {
    uint16_t id;
    uint16_t opts;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/* DNS question structure */
struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
};

/* GRE header */
struct grehdr {
    uint16_t flags;
    uint16_t protocol;
};

/* Pseudo header for checksum calculation */
struct pseudo_header {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};

#endif
