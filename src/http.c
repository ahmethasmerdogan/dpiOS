#include "dpios.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *k_methods[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ",
    "PATCH ", "TRACE ", "CONNECT ", NULL
};

static bool memcaseeq(const uint8_t *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (tolower(a[i]) != tolower((unsigned char)b[i]))
            return false;
    return true;
}

bool dp_http_parse(const uint8_t *payload, size_t len, dp_http_info_t *out)
{
    memset(out, 0, sizeof(*out));

    if (len < 16)
        return false;

    size_t mlen = 0;
    for (int i = 0; k_methods[i]; i++) {
        size_t l = strlen(k_methods[i]);
        if (len > l && memcmp(payload, k_methods[i], l) == 0) {
            mlen = l - 1;          /* offset of the space */
            break;
        }
    }
    if (mlen == 0)
        return false;

    out->is_request = true;
    out->method_len = mlen;

    /* Scan header lines for Host. Stop at the end of the header block. */
    size_t i = 0;
    while (i + 1 < len) {
        if (payload[i] == '\r' && payload[i + 1] == '\n') {
            size_t line = i + 2;
            if (line + 1 < len && payload[line] == '\r' && payload[line + 1] == '\n')
                break;             /* end of headers */
            if (line + 5 <= len && memcaseeq(payload + line, "host:", 5)) {
                out->host_name_off = line;
                size_t v = line + 5;
                while (v < len && (payload[v] == ' ' || payload[v] == '\t'))
                    v++;
                size_t e = v;
                while (e < len && payload[e] != '\r' && payload[e] != '\n')
                    e++;
                out->host_value_off = v;
                out->host_value_len = e - v;
                size_t copy = out->host_value_len;
                if (copy > sizeof(out->host) - 1)
                    copy = sizeof(out->host) - 1;
                memcpy(out->host, payload + v, copy);
                out->host[copy] = '\0';
                /* strip an optional :port suffix for list matching */
                char *colon = strchr(out->host, ':');
                if (colon)
                    *colon = '\0';
                return true;
            }
            i = line;
            continue;
        }
        i++;
    }

    return true;   /* request without a Host header we could find */
}

/*
 * Header mangling, in place, length preserving.
 *
 * Length preservation matters more here than it does on Windows: the kernel's
 * TCP stack has already accounted for exactly `len` bytes at this sequence
 * number. Hand the server one byte more or less and every following segment
 * lands at the wrong offset. So the "remove the space after Host:" and "add a
 * space after the method" tricks are always applied as a pair - one byte out,
 * one byte in.
 */
size_t dp_http_mangle(uint8_t *payload, size_t len, size_t cap,
                      const dp_http_info_t *info, const dp_config_t *c)
{
    (void)cap;

    if (!info->is_request)
        return len;

    if (c->host_replace && info->host_name_off) {
        /* "Host:" -> "hoSt:" ; same length, different bytes on the wire */
        payload[info->host_name_off + 0] = 'h';
        payload[info->host_name_off + 1] = 'o';
        payload[info->host_name_off + 2] = 'S';
        payload[info->host_name_off + 3] = 't';
    }

    if (c->host_case && info->host_value_len) {
        for (size_t i = 0; i < info->host_value_len; i++) {
            uint8_t *ch = &payload[info->host_value_off + i];
            if (*ch >= 'a' && *ch <= 'z' && (i & 1) == 0)
                *ch = (uint8_t)(*ch - 32);
            else if (*ch >= 'A' && *ch <= 'Z' && (i & 1) == 1)
                *ch = (uint8_t)(*ch + 32);
        }
    }

    if ((c->host_nospace || c->method_space) && info->host_name_off &&
        info->host_value_off > info->host_name_off + 5) {
        /*
         * Shift everything between "method<sp>" and the start of the host
         * value one byte to the right. That swallows exactly one space in
         * front of the host value and opens exactly one byte right after the
         * method - net length change: zero.
         */
        size_t from = info->method_len;                /* the space after GET */
        size_t to = info->host_value_off - 1;
        if (to > from && to < len) {
            memmove(payload + from + 1, payload + from, to - from);
            payload[from] = ' ';
        }
    }

    return len;
}

size_t dp_http_build_fake(uint8_t *buf, size_t buflen, const char *host,
                          size_t target_len)
{
    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp),
                     "GET / HTTP/1.1\r\nHost: %s\r\n"
                     "User-Agent: Mozilla/5.0\r\n"
                     "Accept: */*\r\n", host);
    if (n < 0)
        return 0;
    size_t used = (size_t)n;

    /* Pad with a throwaway header so the decoy matches the real size. */
    if (target_len > used + 12 && target_len < sizeof(tmp) - 4) {
        size_t pad = target_len - used - 4 - 8;   /* "X-Pad: " + CRLF + CRLF */
        int k = snprintf(tmp + used, sizeof(tmp) - used, "X-Pad: ");
        used += (size_t)k;
        for (size_t i = 0; i < pad && used < sizeof(tmp) - 4; i++)
            tmp[used++] = 'a';
        tmp[used++] = '\r';
        tmp[used++] = '\n';
    }
    if (used + 2 < sizeof(tmp)) {
        tmp[used++] = '\r';
        tmp[used++] = '\n';
    }

    if (used > buflen)
        used = buflen;
    memcpy(buf, tmp, used);
    return used;
}
