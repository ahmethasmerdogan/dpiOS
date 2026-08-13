#include "dpios.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PFCTL "/sbin/pfctl"

static char s_token[64];
static bool s_rules_loaded = false;

/*
 * pfctl -E enables pf with a reference count and hands back a token, so we do
 * not clobber whatever else on the system (Internet Sharing, a VPN client)
 * might be relying on pf being up. -X <token> gives our reference back.
 */
bool dp_pf_enable(void)
{
    char out[4096];
    const char *argv[] = { PFCTL, "-E", NULL };

    int rc = dp_run_capture(argv, out, sizeof(out));
    if (rc != 0) {
        LOGE("pfctl -E failed (exit %d): %s", rc, out);
        return false;
    }

    /* the token shows up as "Token : 1234567890" */
    const char *p = strstr(out, "Token");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '\t')
                p++;
            size_t i = 0;
            while (p[i] && p[i] >= '0' && p[i] <= '9' && i < sizeof(s_token) - 1) {
                s_token[i] = p[i];
                i++;
            }
            s_token[i] = '\0';
        }
    }

    if (s_token[0])
        LOGD("pf enabled, token %s", s_token);
    else
        LOGW("pf enabled but no token returned - will not disable it on exit");

    return true;
}

/*
 * Our rules live in the anchor "com.apple/dpios". macOS ships a wildcard
 * anchor line - anchor "com.apple/" followed by a star - in /etc/pf.conf, so
 * anything nested under com.apple/ is evaluated without having to edit the
 * system ruleset.
 */
bool dp_pf_anchor_reachable(void)
{
    char out[65536];
    const char *argv[] = { PFCTL, "-s", "rules", NULL };

    if (dp_run_capture(argv, out, sizeof(out)) != 0)
        return false;

    return strstr(out, "com.apple/*") != NULL;
}

static void build_rules(const dp_config_t *c, const dp_utun_t *t,
                        const dp_netinfo_t *ni, char *buf, size_t buflen)
{
    char ports[512] = {0};
    size_t n = 0;
    for (int i = 0; i < c->nports; i++) {
        int k = snprintf(ports + n, sizeof(ports) - n, "%s%u",
                         i ? ", " : "", (unsigned)c->ports[i]);
        if (k < 0)
            break;
        n += (size_t)k;
    }

    /*
     * Never touch anything that is not headed for the open internet: LAN
     * hosts, loopback, link-local, CGNAT and multicast all stay on the normal
     * path. This also means BPF injection can always aim at the default
     * gateway instead of resolving per-destination link layer addresses.
     */
    const char *skip4 =
        "{ 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
        "169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 198.18.0.0/15, "
        "255.255.255.255 }";

    size_t off = 0;
    off += (size_t)snprintf(buf + off, buflen - off,
        "# dpiOS generated ruleset - safe to flush with:\n"
        "#   sudo pfctl -a %s -F all\n", DPIOS_ANCHOR);

    if (c->inject_mode == INJECT_RAW) {
        /*
         * Re-injected packets go back through the routing table, so they have
         * to be recognisable or they would loop straight back into utun. We
         * stamp them with a DSCP mark and let them past untouched.
         */
        off += (size_t)snprintf(buf + off, buflen - off,
            "pass out quick on %s inet proto tcp tos 0x04 no state\n",
            ni->egress.name);
    }

    off += (size_t)snprintf(buf + off, buflen - off,
        "pass out quick on %s route-to (%s %s) inet proto tcp "
        "from any to ! %s port { %s } no state\n",
        ni->egress.name, t->name, t->peer_ip, skip4, ports);

    if (c->enable_ipv6 && t->peer_ip6[0]) {
        off += (size_t)snprintf(buf + off, buflen - off,
            "pass out quick on %s route-to (%s %s) inet6 proto tcp "
            "from any to ! { ::1, fe80::/10, fc00::/7, ff00::/8 } "
            "port { %s } no state\n",
            ni->egress.name, t->name, t->peer_ip6, ports);
    }

    (void)off;
}

bool dp_pf_load_rules(const dp_config_t *c, const dp_utun_t *t,
                      const dp_netinfo_t *ni)
{
    char rules[8192];
    build_rules(c, t, ni, rules, sizeof(rules));

    LOGD("pf ruleset:\n%s", rules);

    char out[4096];
    const char *argv[] = { PFCTL, "-a", DPIOS_ANCHOR, "-f", "-", NULL };
    int rc = dp_run_feed(argv, rules, out, sizeof(out));

    if (rc != 0) {
        LOGE("pfctl failed to load the dpiOS anchor (exit %d)", rc);
        if (out[0])
            LOGE("pfctl said: %s", out);
        LOGE("ruleset was:\n%s", rules);
        return false;
    }
    if (out[0] && dp_log_level() >= DP_DEBUG)
        LOGD("pfctl: %s", out);

    s_rules_loaded = true;
    LOGI("pf anchor %s loaded (%d port%s diverted to %s)",
         DPIOS_ANCHOR, c->nports, c->nports == 1 ? "" : "s", t->name);
    return true;
}

/*
 * This must run on every exit path. A stale route-to rule pointing at a utun
 * that no longer exists is exactly how you black-hole a machine's web traffic.
 */
void dp_pf_unload(void)
{
    if (s_rules_loaded) {
        const char *argv[] = { PFCTL, "-a", DPIOS_ANCHOR, "-F", "all", NULL };
        int rc = dp_run(argv);
        if (rc != 0)
            LOGE("could not flush the dpiOS anchor - run: "
                 "sudo pfctl -a %s -F all", DPIOS_ANCHOR);
        else
            LOGI("pf anchor %s flushed", DPIOS_ANCHOR);
        s_rules_loaded = false;
    }

    if (s_token[0]) {
        const char *argv[] = { PFCTL, "-X", s_token, NULL };
        dp_run(argv);
        s_token[0] = '\0';
    }
}
