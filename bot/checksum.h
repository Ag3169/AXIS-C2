#ifndef _CHECKSUM_H
#define _CHECKSUM_H

#include "includes.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

uint16_t checksum_generic(uint16_t *addr, uint32_t count);
uint16_t checksum_tcpudp(struct iphdr *iph, uint16_t *buff, uint16_t data_len, uint16_t len);
uint16_t checksum_icmp(uint16_t *addr, uint16_t count);

#endif
