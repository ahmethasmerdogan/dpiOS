/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
#include "dpios.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char   **slots;
    size_t   cap;
    size_t   count;
} hostset_t;

static hostset_t s_black = {0};
static hostset_t s_white = {0};

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    for (; *s; s++) {
        h ^= (uint64_t)(unsigned char)tolower((unsigned char)*s);
        h *= 1099511628211ULL;
    }
    return h;
}

static bool set_init(hostset_t *hs, size_t cap)
{
    size_t n = 64;
    while (n < cap * 2)
        n <<= 1;
    hs->slots = calloc(n, sizeof(char *));
    if (!hs->slots)
        return false;
    hs->cap = n;
    hs->count = 0;
    return true;
}

static bool set_grow(hostset_t *hs)
{
    size_t ncap = hs->cap * 2;
    char **ns = calloc(ncap, sizeof(char *));
    if (!ns)
        return false;
    for (size_t i = 0; i < hs->cap; i++) {
        if (!hs->slots[i])
            continue;
        size_t j = (size_t)(fnv1a(hs->slots[i]) & (ncap - 1));
        while (ns[j])
            j = (j + 1) & (ncap - 1);
        ns[j] = hs->slots[i];
    }
    free(hs->slots);
    hs->slots = ns;
    hs->cap = ncap;
    return true;
}

static bool set_add(hostset_t *hs, const char *s)
{
    if (!hs->slots && !set_init(hs, 1024))
        return false;
    if (hs->count * 2 >= hs->cap && !set_grow(hs))
        return false;

    size_t i = (size_t)(fnv1a(s) & (hs->cap - 1));
    while (hs->slots[i]) {
        if (strcasecmp(hs->slots[i], s) == 0)
            return true;
        i = (i + 1) & (hs->cap - 1);
    }
    hs->slots[i] = strdup(s);
    if (!hs->slots[i])
        return false;
    hs->count++;
    return true;
}

static bool set_has(const hostset_t *hs, const char *s)
{
    if (!hs->slots || hs->count == 0)
        return false;
    size_t i = (size_t)(fnv1a(s) & (hs->cap - 1));
    while (hs->slots[i]) {
        if (strcasecmp(hs->slots[i], s) == 0)
            return true;
        i = (i + 1) & (hs->cap - 1);
    }
    return false;
}

static void set_free(hostset_t *hs)
{
    if (!hs->slots)
        return;
    for (size_t i = 0; i < hs->cap; i++)
        free(hs->slots[i]);
    free(hs->slots);
    memset(hs, 0, sizeof(*hs));
}

/* "a.b.example.com" matches an entry for "example.com" */
static bool set_match_suffix(const hostset_t *hs, const char *host)
{
    if (!hs->slots || hs->count == 0)
        return false;

    const char *p = host;
    while (p && *p) {
        if (set_has(hs, p))
            return true;
        const char *dot = strchr(p, '.');
        if (!dot)
            break;
        p = dot + 1;
    }
    return false;
}

bool dp_list_load(const char *path, bool is_whitelist)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOGE("cannot open %s list: %s", is_whitelist ? "whitelist" : "blacklist", path);
        return false;
    }

    hostset_t *hs = is_whitelist ? &s_white : &s_black;
    char line[1024];
    size_t added = 0;

    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        if (*s == '#' || *s == ';' || *s == '\r' || *s == '\n' || *s == '\0')
            continue;

        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\r' || e[-1] == '\n' || e[-1] == ' ' || e[-1] == '\t'))
            *--e = '\0';
        if (e == s)
            continue;

        /* tolerate "0.0.0.0 host" hosts-file style and leading dots/wildcards */
        char *sp = strpbrk(s, " \t");
        if (sp) {
            *sp = '\0';
            char *rest = sp + 1;
            while (*rest == ' ' || *rest == '\t')
                rest++;
            if (*rest)
                s = rest;
        }
        while (*s == '*' || *s == '.')
            s++;
        if (!*s)
            continue;

        if (set_add(hs, s))
            added++;
    }
    fclose(f);

    LOGI("loaded %zu entries from %s (%s)", added, path,
         is_whitelist ? "whitelist" : "blacklist");
    return added > 0;
}

bool dp_list_have_blacklist(void) { return s_black.count > 0; }
bool dp_list_have_whitelist(void) { return s_white.count > 0; }

bool dp_list_should_process(const char *host)
{
    if (s_white.count > 0 && host && *host) {
        if (set_match_suffix(&s_white, host))
            return false;      /* explicitly excluded from processing */
    }
    if (s_black.count > 0) {
        if (!host || !*host)
            return false;      /* blacklist mode: unknown host, leave it alone */
        return set_match_suffix(&s_black, host);
    }
    return true;
}

void dp_list_free(void)
{
    set_free(&s_black);
    set_free(&s_white);
}
