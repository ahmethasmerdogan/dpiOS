/*
 * dpiOS - GoodbyeDPI-style DPI circumvention for macOS (Apple Silicon)
 *
 * Shared declarations.
 */
#ifndef DPIOS_H
#define DPIOS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DPIOS_VERSION      "0.1.0"
#define DPIOS_ANCHOR       "com.apple/dpios"
#define DPIOS_MAX_PACKET   65536
#define DPIOS_MAX_PORTS    32
#define DPIOS_MAX_FRAGS    8

/* ------------------------------------------------------------------ log */

typedef enum {
    DP_ERR = 0,
    DP_WARN = 1,
    DP_INFO = 2,
    DP_DEBUG = 3,
    DP_TRACE = 4
} dp_level_t;

void dp_log_init(bool use_syslog, dp_level_t level);
void dp_log_setlevel(dp_level_t level);
dp_level_t dp_log_level(void);
void dp_log(dp_level_t lvl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* When a sink is installed it takes over rendering; used by the live panel
 * so log lines do not tear through the middle of it. */
typedef void (*dp_log_sink_t)(dp_level_t lvl, const char *msg);
void dp_log_set_sink(dp_log_sink_t fn);

#define LOGE(...) dp_log(DP_ERR, __VA_ARGS__)
#define LOGW(...) dp_log(DP_WARN, __VA_ARGS__)
#define LOGI(...) dp_log(DP_INFO, __VA_ARGS__)
#define LOGD(...) dp_log(DP_DEBUG, __VA_ARGS__)
#define LOGT(...) dp_log(DP_TRACE, __VA_ARGS__)

/* --------------------------------------------------------------- config */

typedef enum {
    INJECT_BPF = 0,   /* raw ethernet frames straight to the NIC (default) */
    INJECT_RAW = 1    /* SOCK_RAW + IP_HDRINCL, marked with DSCP to avoid loops */
} dp_inject_mode_t;

typedef struct {
    /* --- fragmentation --------------------------------------------- */
    int  frag_http;          /* -f N   split HTTP request at byte N (0 = off) */
    int  frag_https;         /* -e N   split TLS ClientHello at byte N (0 = off) */
    int  frag_persistent;    /* -k N   split subsequent HTTP requests too */
    bool frag_sni;           /* --frag-sni  split in the middle of the SNI */
    bool record_frag;        /* split the ClientHello across two TLS records */
    bool reverse_frag;       /* send the second fragment first */
    bool ip_frag;            /* fragment at IP layer instead of TCP layer */

    /* --- HTTP header tricks ----------------------------------------- */
    bool host_case;          /* -m  mixed case host value */
    bool host_replace;       /* -r  "Host:" -> "hoSt:" */
    bool host_nospace;       /* -s  remove space after "Host:" */
    bool method_space;       /* -a  extra space between method and URI */

    /* --- fake packets ----------------------------------------------- */
    bool     fake_enable;
    int      fake_resend;    /* how many times to send the decoy */
    int      fake_ttl;       /* --set-ttl N (0 = don't touch ttl) */
    bool     auto_ttl;
    int      auto_ttl_delta;
    int      auto_ttl_min;
    int      auto_ttl_max;
    bool     wrong_chksum;   /* decoy carries a broken TCP checksum */
    bool     wrong_seq;      /* decoy carries an out-of-window sequence */
    uint32_t wrong_seq_delta;
    char     fake_sni[256];  /* hostname baked into the decoy ClientHello */

    /* --- scope ------------------------------------------------------- */
    uint16_t ports[DPIOS_MAX_PORTS];
    int      nports;
    int      max_payload;    /* skip packets whose payload exceeds this */
    bool     enable_ipv6;
    char     iface[32];      /* forced egress interface, empty = autodetect */
    dp_inject_mode_t inject_mode;

    /* --- dns ---------------------------------------------------------- */
    bool doh;                /* run the local DNS-over-HTTPS resolver */
    char doh_url[256];
    char doh_bootstrap[64];  /* IP of the DoH host, so startup needs no DNS */

    /* --- lists -------------------------------------------------------- */
    char blacklist_path[1024];
    char whitelist_path[1024];

    /* --- runtime ------------------------------------------------------ */
    bool foreground;
    bool use_syslog;
    bool no_ui;              /* force plain log output even on a terminal */
    bool dry_run;            /* parse + decide, but forward untouched */
    int  preset;
    int  action;             /* dp_action_t */
} dp_config_t;

typedef enum {
    DP_ACTION_RUN = 0,
    DP_ACTION_CHECK,
    DP_ACTION_UNLOAD
} dp_action_t;

extern dp_config_t g_cfg;

void dp_config_defaults(dp_config_t *c);
bool dp_config_apply_preset(dp_config_t *c, int preset);
bool dp_config_add_port(dp_config_t *c, int port);
bool dp_config_has_port(const dp_config_t *c, uint16_t port);
void dp_config_dump(const dp_config_t *c);

/* ------------------------------------------------------------------- cli */

int  dp_cli_parse(int argc, char **argv, dp_config_t *c);
void dp_usage(const char *argv0);

/* -------------------------------------------------------------- checksum */

uint16_t dp_cksum_finish(uint32_t sum);
uint32_t dp_cksum_partial(const void *data, size_t len, uint32_t sum);
void dp_fix_checksums_v4(uint8_t *pkt, size_t len);
void dp_fix_checksums_v6(uint8_t *pkt, size_t len);
void dp_fix_checksums(uint8_t *pkt, size_t len, int af);

/* ---------------------------------------------------------------- netinfo */

typedef struct {
    char     name[32];        /* en0 */
    int      index;
    uint8_t  mac[6];
    bool     has_mac;
    int      mtu;
    struct in_addr  addr4;
    struct in_addr  mask4;
    bool     has_addr4;
    struct in6_addr addr6;
    bool     has_addr6;
} dp_iface_t;

typedef struct {
    dp_iface_t egress;
    struct in_addr  gw4;
    bool     has_gw4;
    uint8_t  gw_mac[6];
    bool     has_gw_mac;
    struct in6_addr gw6;
    bool     has_gw6;
    uint8_t  gw6_mac[6];
    bool     has_gw6_mac;
} dp_netinfo_t;

extern dp_netinfo_t g_net;

bool dp_net_discover(dp_netinfo_t *ni, const char *forced_iface);
bool dp_net_refresh_gw_mac(dp_netinfo_t *ni);
bool dp_net_lookup_mac(int af, const void *addr, uint8_t mac[6]);
const char *dp_mac_str(const uint8_t mac[6], char *buf, size_t buflen);

/* ------------------------------------------------------------------- utun */

typedef struct {
    int  fd;
    char name[32];
    char local_ip[64];
    char peer_ip[64];
    char peer_ip6[80];
    int  mtu;
} dp_utun_t;

bool dp_utun_open(dp_utun_t *t, int mtu, bool want_ipv6);
void dp_utun_close(dp_utun_t *t);
ssize_t dp_utun_read(dp_utun_t *t, uint8_t *buf, size_t buflen, int *af_out);

/* --------------------------------------------------------------------- pf */

bool dp_pf_enable(void);
bool dp_pf_load_rules(const dp_config_t *c, const dp_utun_t *t, const dp_netinfo_t *ni);
void dp_pf_unload(void);
bool dp_pf_anchor_reachable(void);

/* ----------------------------------------------------------------- inject */

bool dp_inject_init(const dp_config_t *c, const dp_netinfo_t *ni);
void dp_inject_close(void);
bool dp_inject_packet(const uint8_t *pkt, size_t len, int af);
uint64_t dp_inject_count(void);
uint64_t dp_inject_errors(void);

/* ---------------------------------------------------------------- monitor */

bool dp_monitor_start(const dp_netinfo_t *ni);
void dp_monitor_stop(void);
int  dp_monitor_fd(void);
void dp_monitor_drain(void);
/* returns estimated hop count to peer, or -1 when unknown */
int  dp_monitor_hops(const void *addr, int af);

/* -------------------------------------------------------------------- tls */

typedef struct {
    bool    is_client_hello;
    size_t  sni_offset;      /* offset of the SNI string inside the TCP payload */
    size_t  sni_len;
    char    sni[256];
    size_t  record_len;      /* total TLS record length incl. 5 byte header */
} dp_tls_info_t;

bool dp_tls_parse(const uint8_t *payload, size_t len, dp_tls_info_t *out);
/* re-frames one ClientHello record into two, same total length; 0 = not possible */
size_t dp_tls_split_records(uint8_t *buf, size_t len, size_t cap);
size_t dp_tls_build_fake_hello(uint8_t *buf, size_t buflen, const char *sni, size_t target_len);

/* ------------------------------------------------------------------- http */

typedef struct {
    bool   is_request;
    size_t method_len;       /* offset of the space after the method */
    size_t host_name_off;    /* offset of "Host" token */
    size_t host_value_off;   /* offset of the hostname value */
    size_t host_value_len;
    char   host[256];
} dp_http_info_t;

bool dp_http_parse(const uint8_t *payload, size_t len, dp_http_info_t *out);
/* rewrites in place where possible; returns new length (may grow by 1 for -a) */
size_t dp_http_mangle(uint8_t *payload, size_t len, size_t cap,
                      const dp_http_info_t *info, const dp_config_t *c);
size_t dp_http_build_fake(uint8_t *buf, size_t buflen, const char *host, size_t target_len);

/* -------------------------------------------------------------- blacklist */

bool dp_list_load(const char *path, bool is_whitelist);
/* true when the hostname should be processed */
bool dp_list_should_process(const char *host);
void dp_list_free(void);
bool dp_list_have_blacklist(void);
bool dp_list_have_whitelist(void);

/* ----------------------------------------------------------------- engine */

typedef struct {
    uint64_t seen;
    uint64_t passthrough;
    uint64_t http_hits;
    uint64_t tls_hits;
    uint64_t fakes_sent;
    uint64_t frags_sent;
    uint64_t record_splits;
    uint64_t skipped_list;
    uint64_t oversized;
} dp_stats_t;

extern dp_stats_t g_stats;

void dp_engine_init(const dp_config_t *c);
void dp_engine_handle(uint8_t *pkt, size_t len, int af);
void dp_engine_stats_dump(void);

/* -------------------------------------------------------------------- dns */

bool dp_dns_start(const dp_config_t *c);
void dp_dns_stop(void);
bool dp_dns_active(void);
uint64_t dp_dns_queries(void);

/* --------------------------------------------------------------------- ui */

bool dp_ui_start(const dp_config_t *c, const dp_netinfo_t *ni,
                 const dp_utun_t *t);
void dp_ui_tick(void);
void dp_ui_event(bool is_tls, const char *host, size_t split);
void dp_ui_stop(void);
bool dp_ui_active(void);

/* ------------------------------------------------------------------- util */

/* fork/exec helpers - no shell involved anywhere */
int  dp_run(const char *const argv[]);
int  dp_run_capture(const char *const argv[], char *out, size_t outlen);
int  dp_run_feed(const char *const argv[], const char *stdin_data,
                 char *out, size_t outlen);

/* ------------------------------------------------------------------ check */

int dp_selftest(const dp_config_t *c);

#endif /* DPIOS_H */
