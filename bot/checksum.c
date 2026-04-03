#include "includes.h"
#include "checksum.h"

uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register unsigned long sum = 0;
    
    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
    
    if (count == 1)
        sum += (uint16_t)*(uint8_t *)addr;
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

uint16_t checksum_tcpudp(struct iphdr *iph, uint16_t *buff, uint16_t data_len, uint16_t len) {
    const uint16_t *buf = buff;
    uint32_t sum = 0;
    uint16_t proto = iph->protocol;
    
    // Add source IP
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    
    // Add destination IP
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    
    // Add protocol and length
    sum += htons(proto);
    sum += htons(len);
    
    // Add TCP/UDP data
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    // Add padding if needed
    if (len == 1)
        sum += *(uint8_t *)buf;
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

uint16_t checksum_icmp(uint16_t *addr, uint16_t count) {
    return checksum_generic(addr, count);
}
