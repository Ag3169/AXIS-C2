#include "includes.h"
#include "util.h"

int util_strlen(char *str) {
    int c = 0;
    while (*str++ != 0) c++;
    return c;
}

int util_strcmp(char *str1, char *str2) {
    int len1 = util_strlen(str1);
    int len2 = util_strlen(str2);
    if (len1 != len2) return 0;
    for (int i = 0; i < len1; i++) {
        if (str1[i] != str2[i]) return 0;
    }
    return 1;
}

int util_strncmp(char *str1, char *str2, int len) {
    for (int i = 0; i < len; i++) {
        if (str1[i] != str2[i]) return 0;
    }
    return 1;
}

char *util_strcpy(char *dst, char *src) {
    char *ret = dst;
    while (*src != 0) *dst++ = *src++;
    *dst = 0;
    return ret;
}

char *util_strcat(char *dest, char *src) {
    char *ret = dest;
    while (*dest != 0) dest++;
    while (*src != 0) *dest++ = *src++;
    *dest = 0;
    return ret;
}

void *util_memcpy(void *dst, void *src, int len) {
    char *d = (char *)dst;
    char *s = (char *)src;
    while (len-- > 0) *d++ = *s++;
    return dst;
}

void util_zero(void *dst, int len) {
    char *d = (char *)dst;
    while (len-- > 0) *d++ = 0;
}

int util_atoi(char *str) {
    int res = 0;
    int sign = 1;
    int i = 0;
    
    if (str[0] == '-') { sign = -1; i++; }
    
    for (; str[i] != 0; ++i) {
        if (str[i] < '0' || str[i] > '9') return 0;
        res = res * 10 + str[i] - '0';
    }
    return sign * res;
}

char *util_itoa(int num, char *str) {
    int i = 0;
    int is_negative = 0;
    
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }
    
    if (num < 0) {
        is_negative = 1;
        num = -num;
    }
    
    while (num != 0) {
        int rem = num % 10;
        str[i++] = rem + '0';
        num = num / 10;
    }
    
    if (is_negative) str[i++] = '-';
    str[i] = '\0';
    
    // Reverse string
    int start = 0;
    int end = i - 1;
    while (start < end) {
        char t = str[start];
        str[start] = str[end];
        str[end] = t;
        start++;
        end--;
    }
    
    return str;
}

/* Formatted output using vsprintf - added for scanner functions */
int util_sprintf(char *str, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int result = vsprintf(str, format, args);
    va_end(args);
    return result;
}

static int util_memcmp(char *buf1, char *buf2, int len) {
    for (int i = 0; i < len; i++) {
        if (buf1[i] != buf2[i]) return buf1[i] - buf2[i];
    }
    return 0;
}

int util_memsearch(char *buf, int buf_len, char *needle, int needle_len) {
    if (needle_len > buf_len) return -1;
    for (int i = 0; i < buf_len - needle_len + 1; i++) {
        if (util_memcmp(buf + i, needle, needle_len) == 0) return i;
    }
    return -1;
}

char *util_stristr(char *haystack, int haystack_len, char *needle) {
    int needle_len = util_strlen(needle);
    if (needle_len > haystack_len) return NULL;
    
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        char *haystack_pos = haystack + i;
        BOOL match = TRUE;
        
        for (int j = 0; j < needle_len; j++) {
            char h = tolower(haystack_pos[j]);
            char n = tolower(needle[j]);
            if (h != n) {
                match = FALSE;
                break;
            }
        }
        
        if (match) return haystack_pos;
    }
    return NULL;
}

ipv4_t util_local_addr(void) {
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return 0;
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(fd);
        return 0;
    }
    
    if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) == -1) {
        close(fd);
        return 0;
    }
    
    close(fd);
    return addr.sin_addr.s_addr;
}

int util_fdgets(char *buffer, int buffer_size, int fd) {
    int got = 0;
    int total = 0;
    
    while (got < buffer_size - 1) {
        int res = read(fd, buffer + got, 1);
        if (res == -1 || res == 0) break;
        got += res;
        total += res;
        if (buffer[got - 1] == '\n' || buffer[got - 1] == '\r') break;
    }
    
    if (total > 0 && (buffer[total - 1] == '\n' || buffer[total - 1] == '\r')) {
        total--;
    }
    buffer[total] = 0;
    return total;
}

int util_socket_and_bind(char *bind_addr) {
    struct sockaddr_in addr;
    int fd, bind_addr_len;

    fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) return -1;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(bind_addr);
    addr.sin_port = 0;
    bind_addr_len = sizeof(addr);

    if (bind(fd, (struct sockaddr *)&addr, bind_addr_len) == -1) {
        close(fd);
        return -1;
    }

    return fd;
}
