/*
 * Live terminal panel.
 *
 * When stdout is a terminal and the log level is not turned up, dpiOS draws a
 * small status panel that repaints in place instead of scrolling a wall of
 * log lines. The panel is always the last thing on screen, so repainting is
 * "move up, erase to end of display, draw again".
 *
 * Log messages still have to get out. While the panel is up, log output is
 * redirected here through a sink: the panel is erased, the message is printed
 * so it lands in the scrollback, and the panel is drawn again underneath.
 */
#include "dpios.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define UI_EVENTS   6
#define UI_MIN_W    60
#define UI_MAX_W    78

#define C_RESET  "\033[0m"
#define C_DIM    "\033[2m"
#define C_BOLD   "\033[1m"
#define C_CYAN   "\033[36m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_RED    "\033[31m"
#define C_BLUE   "\033[34m"

typedef struct {
    char     when[9];
    bool     is_tls;
    char     host[64];
    size_t   split;
    bool     used;
} ui_event_t;

static bool        s_active = false;
static int         s_lines = 0;      /* rows the panel currently occupies */
static int         s_width = UI_MAX_W;
static time_t      s_start = 0;
static ui_event_t  s_events[UI_EVENTS];
static int         s_ev_head = 0;
static char        s_head_l[128];
static char        s_head_r[64];
static char        s_sub[192];

bool dp_ui_active(void) { return s_active; }

static int term_width(void)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        int w = ws.ws_col - 2;
        if (w > UI_MAX_W) w = UI_MAX_W;
        if (w < UI_MIN_W) w = UI_MIN_W;
        return w;
    }
    return UI_MAX_W;
}

static void hline(int n)
{
    for (int i = 0; i < n; i++)
        fputs("─", stdout);
}

/* Columns, not bytes: the panel mixes ASCII with box-drawing characters. */
static int utf8_cols(const char *s)
{
    int n = 0;
    for (; *s; s++)
        if (((unsigned char)*s & 0xc0) != 0x80)
            n++;
    return n;
}

/* 1284 -> "1,284" */
static const char *fmt_num(uint64_t v, char *buf, size_t buflen)
{
    char raw[32];
    snprintf(raw, sizeof(raw), "%llu", (unsigned long long)v);

    size_t n = strlen(raw);
    size_t out = 0;
    for (size_t i = 0; i < n && out + 2 < buflen; i++) {
        if (i > 0 && (n - i) % 3 == 0)
            buf[out++] = ',';
        buf[out++] = raw[i];
    }
    buf[out] = '\0';
    return buf;
}

static void bar(const char *color, const char *label, uint64_t value,
                uint64_t scale, int cells)
{
    char num[32];
    int filled = 0;
    if (scale > 0) {
        filled = (int)((value * (uint64_t)cells) / scale);
        if (filled > cells) filled = cells;
        if (filled == 0 && value > 0) filled = 1;
    }

    printf("  %s%-7s%s %s%6s%s  %s",
           C_DIM, label, C_RESET, C_BOLD, fmt_num(value, num, sizeof(num)),
           C_RESET, color);
    for (int i = 0; i < filled; i++)
        fputs("█", stdout);
    fputs(C_DIM, stdout);
    for (int i = filled; i < cells; i++)
        fputs("░", stdout);
    printf("%s\n", C_RESET);
}

static void erase_panel(void)
{
    if (s_lines > 0)
        printf("\033[%dA\033[J", s_lines);
    s_lines = 0;
}

static void draw_panel(void)
{
    s_width = term_width();
    int inner = s_width - 2;

    /*
     * Top row is: corner + one dash + " title " + dashes + " right " + corner.
     * That is 7 fixed columns on top of the two labels, and the row has to
     * come out the same width as the plain rule below it.
     */
    int lw = utf8_cols(s_head_l);
    int rw = utf8_cols(s_head_r);
    int dashes = inner - lw - rw - 5;
    if (dashes < 1) dashes = 1;

    printf("%s╭", C_CYAN);
    hline(1);
    printf("%s %s%s%s ", C_RESET, C_BOLD, s_head_l, C_RESET);
    printf("%s", C_CYAN);
    hline(dashes);
    printf(" %s%s%s %s╮%s\n", C_DIM, s_head_r, C_RESET, C_CYAN, C_RESET);

    int pad = inner - 2 - utf8_cols(s_sub);
    if (pad < 0) pad = 0;
    printf("%s│%s %s%*s %s│%s\n",
           C_CYAN, C_RESET, s_sub, pad, "", C_CYAN, C_RESET);

    printf("%s╰", C_CYAN);
    hline(inner);
    printf("╯%s\n\n", C_RESET);
    s_lines = 4;

    /* ---- counters ---- */
    char n1[32], n2[32];
    long up = (long)(time(NULL) - s_start);
    printf("  %suptime%s %02ld:%02ld:%02ld   %sinjected%s %s   %serrors%s %s%s%s\n\n",
           C_DIM, C_RESET, up / 3600, (up / 60) % 60, up % 60,
           C_DIM, C_RESET, fmt_num(dp_inject_count(), n1, sizeof(n1)),
           C_DIM, C_RESET,
           dp_inject_errors() ? C_RED : "",
           fmt_num(dp_inject_errors(), n2, sizeof(n2)),
           dp_inject_errors() ? C_RESET : "");
    s_lines += 2;

    /* ---- traffic bars ---- */
    uint64_t scale = g_stats.tls_hits > g_stats.http_hits
                   ? g_stats.tls_hits : g_stats.http_hits;
    int cells = s_width - 20;
    if (cells < 10) cells = 10;
    if (cells > 40) cells = 40;

    bar(C_GREEN, "TLS", g_stats.tls_hits, scale, cells);
    bar(C_YELLOW, "HTTP", g_stats.http_hits, scale, cells);
    s_lines += 2;

    char n3[32], n4[32], n5[32];
    printf("  %sdecoys%s %s   %sfragments%s %s   %suntouched%s %s\n\n",
           C_DIM, C_RESET, fmt_num(g_stats.fakes_sent, n3, sizeof(n3)),
           C_DIM, C_RESET, fmt_num(g_stats.frags_sent, n4, sizeof(n4)),
           C_DIM, C_RESET, fmt_num(g_stats.passthrough, n5, sizeof(n5)));
    s_lines += 2;

    /* ---- recent activity ---- */
    printf("  %srecent%s\n", C_DIM, C_RESET);
    s_lines += 1;

    int shown = 0;
    for (int i = 0; i < UI_EVENTS; i++) {
        int idx = (s_ev_head - 1 - i + UI_EVENTS * 2) % UI_EVENTS;
        const ui_event_t *e = &s_events[idx];
        if (!e->used)
            continue;

        int hostw = s_width - 34;
        if (hostw < 12) hostw = 12;
        if (hostw > 40) hostw = 40;

        printf("    %s%s%s  %s%-4s%s  %-*.*s %ssplit @ %zu%s\n",
               C_DIM, e->when, C_RESET,
               e->is_tls ? C_GREEN : C_YELLOW, e->is_tls ? "TLS" : "HTTP",
               C_RESET, hostw, hostw, e->host,
               C_DIM, e->split, C_RESET);
        shown++;
        s_lines++;
    }
    if (shown == 0) {
        printf("    %swaiting for traffic...%s\n", C_DIM, C_RESET);
        s_lines++;
    }

    printf("\n  %sCtrl-C to stop%s\n", C_DIM, C_RESET);
    s_lines += 2;

    fflush(stdout);
}

/* Log lines have to survive: erase, print into the scrollback, redraw. */
static void ui_log_sink(dp_level_t lvl, const char *msg)
{
    const char *color = (lvl == DP_ERR) ? C_RED
                      : (lvl == DP_WARN) ? C_YELLOW : C_BLUE;
    const char *tag = (lvl == DP_ERR) ? "error"
                    : (lvl == DP_WARN) ? "warn" : "info";

    erase_panel();
    printf("  %s%s%s %s\n", color, tag, C_RESET, msg);
    draw_panel();
}

bool dp_ui_start(const dp_config_t *c, const dp_netinfo_t *ni,
                 const dp_utun_t *t)
{
    if (c->no_ui || c->use_syslog || !isatty(STDOUT_FILENO))
        return false;
    if (dp_log_level() > DP_INFO)
        return false;      /* -v/-vv means the user wants the raw log */

    snprintf(s_head_l, sizeof(s_head_l), "dpiOS %s", DPIOS_VERSION);
    if (c->preset)
        snprintf(s_head_r, sizeof(s_head_r), "preset -%d", c->preset);
    else
        snprintf(s_head_r, sizeof(s_head_r), "custom");

    char ports[64] = {0};
    size_t n = 0;
    for (int i = 0; i < c->nports && n < sizeof(ports) - 1; i++)
        n += (size_t)snprintf(ports + n, sizeof(ports) - n, "%s%u",
                              i ? "," : "", (unsigned)c->ports[i]);

    snprintf(s_sub, sizeof(s_sub), "%s → %s    ports %s    decoys %s",
             ni->egress.name, t->name, ports,
             c->fake_enable ? (c->auto_ttl ? "on, auto-ttl" : "on") : "off");

    memset(s_events, 0, sizeof(s_events));
    s_ev_head = 0;
    s_start = time(NULL);
    s_lines = 0;
    s_active = true;

    dp_log_set_sink(ui_log_sink);
    draw_panel();
    return true;
}

void dp_ui_tick(void)
{
    if (!s_active)
        return;
    erase_panel();
    draw_panel();
}

void dp_ui_event(bool is_tls, const char *host, size_t split)
{
    if (!s_active)
        return;

    ui_event_t *e = &s_events[s_ev_head];
    s_ev_head = (s_ev_head + 1) % UI_EVENTS;

    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(e->when, sizeof(e->when), "%H:%M:%S", &tmv);

    e->is_tls = is_tls;
    e->split = split;
    strlcpy(e->host, (host && *host) ? host : "(no hostname)", sizeof(e->host));
    e->used = true;
}

void dp_ui_stop(void)
{
    if (!s_active)
        return;

    dp_log_set_sink(NULL);
    s_active = false;

    /* leave the final panel on screen, then carry on with plain logging */
    erase_panel();
    draw_panel();
    printf("\n");
    fflush(stdout);
}
