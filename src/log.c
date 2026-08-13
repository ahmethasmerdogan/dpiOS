#include "dpios.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

static bool         s_syslog = false;
static dp_level_t   s_level = DP_INFO;
static dp_log_sink_t s_sink = NULL;

static const char *level_name(dp_level_t l)
{
    switch (l) {
    case DP_ERR:   return "ERROR";
    case DP_WARN:  return "WARN ";
    case DP_INFO:  return "INFO ";
    case DP_DEBUG: return "DEBUG";
    default:       return "TRACE";
    }
}

static int level_syslog(dp_level_t l)
{
    switch (l) {
    case DP_ERR:   return LOG_ERR;
    case DP_WARN:  return LOG_WARNING;
    case DP_INFO:  return LOG_NOTICE;
    default:       return LOG_DEBUG;
    }
}

void dp_log_init(bool use_syslog, dp_level_t level)
{
    s_syslog = use_syslog;
    s_level = level;
    if (use_syslog)
        openlog("dpios", LOG_PID, LOG_DAEMON);
}

void dp_log_setlevel(dp_level_t level) { s_level = level; }
dp_level_t dp_log_level(void) { return s_level; }
void dp_log_set_sink(dp_log_sink_t fn) { s_sink = fn; }

void dp_log(dp_level_t lvl, const char *fmt, ...)
{
    if (lvl > s_level)
        return;

    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (s_syslog)
        syslog(level_syslog(lvl), "%s", msg);

    if (s_sink) {
        s_sink(lvl, msg);
        return;
    }

    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tmv);

    FILE *out = (lvl <= DP_WARN) ? stderr : stdout;
    fprintf(out, "%s [%s] %s\n", ts, level_name(lvl), msg);
    fflush(out);
}
