/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
/*
 * --check walks every macOS-specific mechanism dpiOS depends on and reports
 * which ones work on this machine. Everything it creates is torn down again
 * before it returns, so it is safe to run at any time.
 */
#include "dpios.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int s_fail = 0;
static int s_warn = 0;

static void ok(const char *what, const char *detail)
{
    printf("  \033[32mok\033[0m    %-28s %s\n", what, detail ? detail : "");
}

static void warn(const char *what, const char *detail)
{
    s_warn++;
    printf("  \033[33mwarn\033[0m  %-28s %s\n", what, detail ? detail : "");
}

static void fail(const char *what, const char *detail)
{
    s_fail++;
    printf("  \033[31mFAIL\033[0m  %-28s %s\n", what, detail ? detail : "");
}

int dp_selftest(const dp_config_t *cfg)
{
    char detail[512];
    dp_utun_t tun = { .fd = -1 };
    dp_netinfo_t ni;

    printf("dpiOS %s self-test\n\n", DPIOS_VERSION);

    /* ---------------------------------------------------------- privileges */
    if (geteuid() == 0)
        ok("root privileges", "running as uid 0");
    else
        fail("root privileges", "re-run with sudo");

    /* ------------------------------------------------------------- network */
    if (dp_net_discover(&ni, cfg->iface)) {
        snprintf(detail, sizeof(detail), "%s, mtu %d", ni.egress.name, ni.egress.mtu);
        ok("egress interface", detail);

        if (ni.has_gw4) {
            char gb[64];
            inet_ntop(AF_INET, &ni.gw4, gb, sizeof(gb));
            ok("default gateway", gb);
        } else {
            fail("default gateway", "no IPv4 default route");
        }

        if (ni.egress.has_mac) {
            char mb[32];
            ok("interface hwaddr", dp_mac_str(ni.egress.mac, mb, sizeof(mb)));
        } else {
            warn("interface hwaddr", "not an ethernet-style link; use --inject raw");
        }

        if (ni.has_gw_mac) {
            char mb[32];
            ok("gateway hwaddr", dp_mac_str(ni.gw_mac, mb, sizeof(mb)));
        } else {
            fail("gateway hwaddr", "ARP cache is cold - ping the router and retry");
        }
    } else {
        fail("egress interface", "could not determine the default route");
        memset(&ni, 0, sizeof(ni));
    }

    /* ---------------------------------------------------------------- utun */
    if (dp_utun_open(&tun, ni.egress.mtu > 0 ? ni.egress.mtu : 1500,
                     cfg->enable_ipv6)) {
        snprintf(detail, sizeof(detail), "%s (%s -> %s)",
                 tun.name, tun.local_ip, tun.peer_ip);
        ok("utun interface", detail);
    } else {
        fail("utun interface", "could not attach to the utun kernel control");
    }

    /* ------------------------------------------------------------------ pf */
    if (dp_pf_enable())
        ok("pf enable", "pfctl -E succeeded");
    else
        fail("pf enable", "pfctl -E failed");

    if (dp_pf_anchor_reachable()) {
        ok("anchor com.apple/*", "present in the active ruleset");
    } else {
        fail("anchor com.apple/*",
             "missing - run: sudo pfctl -f /etc/pf.conf");
    }

    /*
     * The interesting one. Everything hinges on whether this build of pf
     * honours route-to for locally generated traffic.
     */
    if (tun.fd >= 0 && ni.egress.name[0]) {
        if (dp_pf_load_rules(cfg, &tun, &ni)) {
            ok("pf route-to rules", "accepted by pfctl");

            char out[16384];
            const char *argv[] = { "/sbin/pfctl", "-a", DPIOS_ANCHOR,
                                   "-s", "rules", NULL };
            if (dp_run_capture(argv, out, sizeof(out)) == 0 &&
                strstr(out, "route-to")) {
                ok("pf rules installed", "route-to visible in the anchor");
            } else {
                warn("pf rules installed",
                     "anchor did not report a route-to rule");
            }
        } else {
            fail("pf route-to rules",
                 "pfctl rejected the ruleset - see the error above");
        }
    } else {
        warn("pf route-to rules", "skipped, prerequisites failed");
    }

    /* ----------------------------------------------------------- injection */
    if (ni.egress.name[0]) {
        if (dp_inject_init(cfg, &ni)) {
            ok("packet injection",
               cfg->inject_mode == INJECT_BPF ? "BPF device opened"
                                              : "raw socket opened");
        } else {
            fail("packet injection",
                 cfg->inject_mode == INJECT_BPF
                     ? "could not open /dev/bpf - try --inject raw"
                     : "could not open a raw socket");
        }
    }

    /* ------------------------------------------------------------- monitor */
    if (ni.egress.name[0]) {
        if (dp_monitor_start(&ni))
            ok("ttl monitor", "passive BPF reader attached");
        else
            warn("ttl monitor", "unavailable; --auto-ttl will use its default");
    }

    /* ------------------------------------------------------------- cleanup */
    dp_monitor_stop();
    dp_inject_close();
    dp_pf_unload();
    dp_utun_close(&tun);

    printf("\n");
    if (s_fail == 0 && s_warn == 0) {
        printf("Everything checks out. Start with: sudo dpios -5\n");
    } else if (s_fail == 0) {
        printf("%d warning(s), no blockers. dpiOS should run.\n", s_warn);
    } else {
        printf("%d failure(s) and %d warning(s). "
               "Fix the failures above before running dpiOS.\n", s_fail, s_warn);
    }

    return s_fail == 0 ? 0 : 1;
}
