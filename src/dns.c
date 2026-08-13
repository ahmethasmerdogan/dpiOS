/*
 * Local DNS-over-HTTPS resolver.
 *
 * Why this exists: the ISP that motivated dpiOS filters DNS by domain suffix,
 * and it follows the query to whatever resolver you point it at. Measured -
 * asking 1.1.1.1 for a blocked name over UDP times out and over TCP gets a
 * reset, while an unblocked name answers fine. Worse, the filter is a
 * wildcard: even a name that does not exist under the blocked domain comes
 * back as the block page address.
 *
 * That last part is what rules out /etc/hosts. A desktop app resolves names it
 * is told about at runtime - gateway.us-east1-b.discord.gg and friends - which
 * no static file can enumerate.
 *
 * So dpiOS answers DNS itself: it listens on 127.0.0.1:53, forwards the query
 * verbatim inside an HTTPS request (RFC 8484) and hands the answer back. The
 * query never appears on the wire in a form the filter can read.
 *
 * The system resolver is pointed at 127.0.0.1 while we run and put back on
 * every exit path - including the fatal-signal path, because leaving the
 * machine pointing at a resolver that is no longer listening would break all
 * name resolution, not just the blocked names.
 */
#include "dpios.h"

#ifndef DPIOS_NO_DOH

#include <curl/curl.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DNS_WORKERS     4
#define DNS_QUEUE       64
#define DNS_MAXMSG      1500
#define DNS_CACHE_SLOTS 512
#define DNS_CACHE_TTL   60

typedef struct {
    uint8_t            msg[DNS_MAXMSG];
    size_t             len;
    struct sockaddr_in from;
    socklen_t          fromlen;
} dns_job_t;

typedef struct {
    uint8_t  key[256];      /* question section, minus the transaction id */
    size_t   keylen;
    uint8_t  answer[DNS_MAXMSG];
    size_t   anslen;
    time_t   stamp;
    bool     used;
} dns_cache_t;

static int             s_sock = -1;
static bool            s_running = false;
static pthread_t       s_listener;
static pthread_t       s_workers[DNS_WORKERS];
static int             s_nworkers = 0;

static dns_job_t       s_queue[DNS_QUEUE];
static int             s_qhead = 0, s_qtail = 0, s_qcount = 0;
static pthread_mutex_t s_qlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_qcond = PTHREAD_COND_INITIALIZER;

static dns_cache_t     s_cache[DNS_CACHE_SLOTS];
static pthread_mutex_t s_clock_ = PTHREAD_MUTEX_INITIALIZER;

static char            s_url[256];
static char            s_resolve[128];
static char            s_service[128];      /* networksetup service name */
static char            s_saved_dns[512];    /* what it was before we touched it */
static bool            s_dns_changed = false;

static uint64_t        s_queries = 0, s_cachehits = 0, s_errors = 0;

/* ---------------------------------------------------------------- cache -- */

/*
 * The cache key is the question section: everything after the 12 byte header
 * up to and including qtype/qclass. The transaction id and the flags are
 * deliberately excluded so two clients asking the same thing share an entry.
 */
static size_t question_key(const uint8_t *msg, size_t len, uint8_t *key, size_t keycap)
{
    if (len < 13)
        return 0;

    size_t i = 12;
    while (i < len && msg[i] != 0) {
        if (msg[i] & 0xc0)          /* compression pointer in a question */
            return 0;
        i += msg[i] + 1;
        if (i > len)
            return 0;
    }
    i += 1 + 4;                     /* root label + qtype + qclass */
    if (i > len || i - 12 > keycap)
        return 0;

    memcpy(key, msg + 12, i - 12);
    return i - 12;
}

static uint32_t key_hash(const uint8_t *k, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= k[i];
        h *= 16777619u;
    }
    return h;
}

static bool cache_get(const uint8_t *key, size_t keylen,
                      uint8_t *out, size_t *outlen)
{
    bool hit = false;
    uint32_t slot = key_hash(key, keylen) % DNS_CACHE_SLOTS;

    pthread_mutex_lock(&s_clock_);
    dns_cache_t *e = &s_cache[slot];
    if (e->used && e->keylen == keylen && memcmp(e->key, key, keylen) == 0 &&
        time(NULL) - e->stamp < DNS_CACHE_TTL) {
        memcpy(out, e->answer, e->anslen);
        *outlen = e->anslen;
        hit = true;
    }
    pthread_mutex_unlock(&s_clock_);
    return hit;
}

static void cache_put(const uint8_t *key, size_t keylen,
                      const uint8_t *ans, size_t anslen)
{
    if (keylen > sizeof(((dns_cache_t *)0)->key) || anslen > DNS_MAXMSG)
        return;

    uint32_t slot = key_hash(key, keylen) % DNS_CACHE_SLOTS;

    pthread_mutex_lock(&s_clock_);
    dns_cache_t *e = &s_cache[slot];
    memcpy(e->key, key, keylen);
    e->keylen = keylen;
    memcpy(e->answer, ans, anslen);
    e->anslen = anslen;
    e->stamp = time(NULL);
    e->used = true;
    pthread_mutex_unlock(&s_clock_);
}

/* ------------------------------------------------------------------ doh -- */

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
} sink_t;

static size_t sink_write(char *data, size_t sz, size_t nm, void *ud)
{
    sink_t *s = (sink_t *)ud;
    size_t n = sz * nm;
    if (s->len + n > s->cap)
        n = s->cap - s->len;
    memcpy(s->buf + s->len, data, n);
    s->len += n;
    return sz * nm;              /* claim it all, or curl aborts the transfer */
}

/* Returns the answer length, or 0 on failure. */
static size_t doh_query(CURL *curl, struct curl_slist *hdrs,
                        struct curl_slist *resolve,
                        const uint8_t *q, size_t qlen,
                        uint8_t *out, size_t outcap)
{
    sink_t sink = { .buf = out, .cap = outcap, .len = 0 };

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, s_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)q);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)qlen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 5000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 4000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    /* the resolver's own name must never need the resolver */
    if (resolve)
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOGD("DoH request failed: %s", curl_easy_strerror(rc));
        return 0;
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code != 200) {
        LOGD("DoH request returned HTTP %ld", code);
        return 0;
    }

    return sink.len;
}

/* --------------------------------------------------------------- worker -- */

static void *worker_main(void *arg)
{
    (void)arg;

    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "content-type: application/dns-message");
    hdrs = curl_slist_append(hdrs, "accept: application/dns-message");

    struct curl_slist *resolve = NULL;
    if (s_resolve[0])
        resolve = curl_slist_append(NULL, s_resolve);

    uint8_t answer[DNS_MAXMSG];
    uint8_t key[256];

    for (;;) {
        pthread_mutex_lock(&s_qlock);
        while (s_qcount == 0 && s_running)
            pthread_cond_wait(&s_qcond, &s_qlock);
        if (!s_running && s_qcount == 0) {
            pthread_mutex_unlock(&s_qlock);
            break;
        }
        dns_job_t job = s_queue[s_qhead];
        s_qhead = (s_qhead + 1) % DNS_QUEUE;
        s_qcount--;
        pthread_mutex_unlock(&s_qlock);

        size_t keylen = question_key(job.msg, job.len, key, sizeof(key));
        size_t anslen = 0;

        if (keylen && cache_get(key, keylen, answer, &anslen)) {
            s_cachehits++;
        } else {
            anslen = doh_query(curl, hdrs, resolve, job.msg, job.len,
                               answer, sizeof(answer));
            if (anslen && keylen)
                cache_put(key, keylen, answer, anslen);
        }

        if (anslen < 12) {
            s_errors++;
            continue;
        }

        /* the cached answer carries somebody else's transaction id */
        answer[0] = job.msg[0];
        answer[1] = job.msg[1];

        sendto(s_sock, answer, anslen, 0,
               (struct sockaddr *)&job.from, job.fromlen);
    }

    curl_slist_free_all(hdrs);
    if (resolve)
        curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    return NULL;
}

static void *listener_main(void *arg)
{
    (void)arg;

    while (s_running) {
        dns_job_t job;
        job.fromlen = sizeof(job.from);
        ssize_t n = recvfrom(s_sock, job.msg, sizeof(job.msg), 0,
                             (struct sockaddr *)&job.from, &job.fromlen);
        if (n <= 0) {
            if (!s_running)
                break;
            if (errno == EINTR)
                continue;
            usleep(10000);
            continue;
        }
        job.len = (size_t)n;
        s_queries++;

        pthread_mutex_lock(&s_qlock);
        if (s_qcount < DNS_QUEUE) {
            s_queue[s_qtail] = job;
            s_qtail = (s_qtail + 1) % DNS_QUEUE;
            s_qcount++;
            pthread_cond_signal(&s_qcond);
        } else {
            s_errors++;          /* queue full: drop, the client will retry */
        }
        pthread_mutex_unlock(&s_qlock);
    }
    return NULL;
}

/* ------------------------------------------------- system dns plumbing -- */

static bool find_service(char *out, size_t outlen)
{
    char dev[64] = {0};
    char buf[8192];

    const char *rargv[] = { "/sbin/route", "-n", "get", "default", NULL };
    if (dp_run_capture(rargv, buf, sizeof(buf)) != 0)
        return false;

    const char *p = strstr(buf, "interface:");
    if (!p)
        return false;
    if (sscanf(p, "interface: %63s", dev) != 1)
        return false;

    const char *nargv[] = { "/usr/sbin/networksetup",
                            "-listnetworkserviceorder", NULL };
    if (dp_run_capture(nargv, buf, sizeof(buf)) != 0)
        return false;

    /*
     * The listing pairs a "(n) Name" line with a following line that names the
     * device, so remember the last name seen and take it when the device
     * matches.
     */
    char want[80];
    snprintf(want, sizeof(want), "Device: %s)", dev);

    char last[128] = {0};
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '(' && strstr(line, ") ")) {
            const char *name = strstr(line, ") ") + 2;
            strlcpy(last, name, sizeof(last));
        } else if (strstr(line, want) && last[0]) {
            strlcpy(out, last, outlen);
            return true;
        }
    }
    return false;
}

static bool point_system_dns_at_us(void)
{
    if (!find_service(s_service, sizeof(s_service))) {
        LOGE("could not work out which network service to configure");
        return false;
    }

    const char *gargv[] = { "/usr/sbin/networksetup", "-getdnsservers",
                            s_service, NULL };
    dp_run_capture(gargv, s_saved_dns, sizeof(s_saved_dns));

    const char *sargv[] = { "/usr/sbin/networksetup", "-setdnsservers",
                            s_service, "127.0.0.1", NULL };
    if (dp_run(sargv) != 0) {
        LOGE("networksetup could not point %s at 127.0.0.1", s_service);
        return false;
    }

    s_dns_changed = true;
    LOGI("system resolver for \"%s\" now points at dpiOS", s_service);
    return true;
}

static void restore_system_dns(void)
{
    if (!s_dns_changed)
        return;

    /* "There aren't any DNS Servers set on X." means it was on automatic */
    bool had_none = (strstr(s_saved_dns, "aren't any") != NULL) ||
                    (strstr(s_saved_dns, "any DNS Servers") != NULL);

    if (had_none) {
        const char *argv[] = { "/usr/sbin/networksetup", "-setdnsservers",
                               s_service, "Empty", NULL };
        dp_run(argv);
    } else {
        /* feed the saved list back, one server per argument */
        const char *argv[16];
        int n = 0;
        argv[n++] = "/usr/sbin/networksetup";
        argv[n++] = "-setdnsservers";
        argv[n++] = s_service;

        char *save = NULL;
        for (char *tok = strtok_r(s_saved_dns, " \t\r\n", &save);
             tok && n < 14; tok = strtok_r(NULL, " \t\r\n", &save)) {
            if (*tok)
                argv[n++] = tok;
        }
        argv[n] = NULL;
        if (n > 3)
            dp_run(argv);
    }

    s_dns_changed = false;
    LOGI("system resolver for \"%s\" restored", s_service);
}

/* ------------------------------------------------------------------ api -- */

bool dp_dns_start(const dp_config_t *c)
{
    if (!c->doh)
        return false;

    strlcpy(s_url, c->doh_url[0] ? c->doh_url
                                 : "https://cloudflare-dns.com/dns-query",
            sizeof(s_url));

    /*
     * Pin the resolver's own address so starting up does not depend on the
     * very name resolution we are about to take over.
     */
    if (c->doh_bootstrap[0]) {
        char host[128];
        strlcpy(host, s_url, sizeof(host));
        char *h = strstr(host, "://");
        h = h ? h + 3 : host;
        char *slash = strchr(h, '/');
        if (slash)
            *slash = '\0';
        snprintf(s_resolve, sizeof(s_resolve), "%s:443:%s", h, c->doh_bootstrap);
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOGE("curl_global_init failed");
        return false;
    }

    s_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_sock < 0) {
        LOGE("DNS socket failed: %s", strerror(errno));
        return false;
    }

    int on = 1;
    setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_len = sizeof(addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOGE("cannot bind 127.0.0.1:53 (%s) - is another resolver running?",
             strerror(errno));
        close(s_sock);
        s_sock = -1;
        return false;
    }

    s_running = true;

    for (int i = 0; i < DNS_WORKERS; i++) {
        if (pthread_create(&s_workers[i], NULL, worker_main, NULL) == 0)
            s_nworkers++;
    }
    if (s_nworkers == 0) {
        LOGE("could not start any DoH worker threads");
        s_running = false;
        close(s_sock);
        s_sock = -1;
        return false;
    }

    if (pthread_create(&s_listener, NULL, listener_main, NULL) != 0) {
        LOGE("could not start the DNS listener thread");
        dp_dns_stop();
        return false;
    }

    if (!point_system_dns_at_us()) {
        dp_dns_stop();
        return false;
    }

    LOGI("DoH resolver listening on 127.0.0.1:53 -> %s", s_url);
    return true;
}

void dp_dns_stop(void)
{
    /* resolver settings go back first: never leave the machine pointing at a
     * socket that is about to close */
    restore_system_dns();

    if (!s_running && s_sock < 0)
        return;

    s_running = false;

    if (s_sock >= 0) {
        shutdown(s_sock, SHUT_RDWR);
        close(s_sock);
        s_sock = -1;
    }

    pthread_mutex_lock(&s_qlock);
    pthread_cond_broadcast(&s_qcond);
    pthread_mutex_unlock(&s_qlock);

    for (int i = 0; i < s_nworkers; i++)
        pthread_join(s_workers[i], NULL);
    s_nworkers = 0;

    LOGI("DoH resolver stopped (%llu queries, %llu cached, %llu errors)",
         (unsigned long long)s_queries,
         (unsigned long long)s_cachehits,
         (unsigned long long)s_errors);
}

bool dp_dns_active(void) { return s_running; }
uint64_t dp_dns_queries(void) { return s_queries; }

#else  /* DPIOS_NO_DOH - used by the Linux cross-build, which has no libcurl */

bool dp_dns_start(const dp_config_t *c)
{
    if (c->doh)
        LOGE("this build was compiled without DoH support");
    return false;
}
void dp_dns_stop(void) {}
bool dp_dns_active(void) { return false; }
uint64_t dp_dns_queries(void) { return 0; }

#endif
