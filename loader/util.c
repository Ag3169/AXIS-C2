#include "includes.h"
#include "util.h"

int util_strlen(char *str) {
    int c = 0;
    while (*str++ != 0) c++;
    return c;
}

char *util_stristr(char *haystack, int haystack_len, char *needle) {
    int needle_len = util_strlen(needle);
    if (needle_len > haystack_len) return NULL;

    for (int i = 0; i <= haystack_len - needle_len; i++) {
        char *pos = haystack + i;
        BOOL match = TRUE;

        for (int j = 0; j < needle_len; j++) {
            char h = tolower(pos[j]);
            char n = tolower(needle[j]);
            if (h != n) {
                match = FALSE;
                break;
            }
        }

        if (match) return pos;
    }
    return NULL;
}

char *util_trim(char *str) {
    char *end;

    while (isspace(*str)) str++;

    if (*str == 0) return str;

    end = str + util_strlen(str) - 1;
    while (end > str && isspace(*end)) end--;

    *(end + 1) = 0;

    return str;
}
