/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
#include "dpios.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>

static dp_utun_t s_tun = { .fd = -1 };
static volatile sig_atomic_t s_stop = 0;
static volatile sig_atomic_t s_dump = 0;
static bool s_cleaned = false;

/*
 * Tearing the pf rules down is not optional. A route-to rule pointing at a
 * utun that no longer exists silently swallows every HTTP and HTTPS packet on
 * the machine, so this runs from the normal exit path, from every signal we
 * catch, and from atexit.
 */
static void cleanup(void)
{
    if (s_cleaned)
        return;
    s_cleaned = true;

    dp_ui_stop();      /* hand the terminal back before anything else logs */
    dp_dns_stop();     /* put the system resolver back before anything else */
    dp_pf_unload();
    dp_utun_close(&s_tun);
    dp_inject_close();
    dp_monitor_stop();
    dp_list_free();
}

static void on_signal(int sig)
{
    if (sig == SIGINFO || sig == SIGUSR1) {
        s_dump = 1;
        return;
    }
    s_stop = sig;
}

static void on_fatal_signal(int sig)
{
    cleanup();
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;                 /* no SA_RESTART: kevent must return */

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINFO, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);

    struct sigaction fatal;
    memset(&fatal, 0, sizeof(fatal));
    fatal.sa_handler = on_fatal_signal;
    sigemptyset(&fatal.sa_mask);
    sigaction(SIGSEGV, &fatal, NULL);
    sigaction(SIGBUS, &fatal, NULL);
    sigaction(SIGABRT, &fatal, NULL);
    sigaction(SIGILL, &fatal, NULL);

    signal(SIGPIPE, SIG_IGN);
}

static int run_loop(void)
{
    int kq = kqueue();
    if (kq < 0) {
        LOGE("kqueue failed: %s", strerror(errno));
        return 1;
    }

    struct kevent ev[3];
    int nev = 0;
    EV_SET(&ev[nev++], s_tun.fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (dp_monitor_fd() >= 0)
        EV_SET(&ev[nev++], dp_monitor_fd(), EVFILT_READ,
               EV_ADD | EV_ENABLE, 0, 0, NULL);
    if (dp_ui_active())
        EV_SET(&ev[nev++], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 250, NULL);

    if (kevent(kq, ev, nev, NULL, 0, NULL) < 0) {
        LOGE("kevent registration failed: %s", strerror(errno));
        close(kq);
        return 1;
    }

    if (!dp_ui_active())
        LOGI("dpiOS is running - press Ctrl-C to stop "
             "(send SIGINFO for live statistics)");

    static uint8_t buf[DPIOS_MAX_PACKET];
    struct kevent out[4];

    while (!s_stop) {
        int n = kevent(kq, NULL, 0, out, 4, NULL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            LOGE("kevent failed: %s", strerror(errno));
            break;
        }

        for (int i = 0; i < n; i++) {
            if (out[i].filter == EVFILT_TIMER) {
                dp_ui_tick();
                continue;
            }
            if ((int)out[i].ident == dp_monitor_fd()) {
                dp_monitor_drain();
                continue;
            }

            /* drain the tunnel; it is non-blocking */
            for (;;) {
                int af = 0;
                ssize_t len = dp_utun_read(&s_tun, buf, sizeof(buf), &af);
                if (len < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    if (errno == EINTR)
                        continue;
                    LOGE("utun read failed: %s", strerror(errno));
                    s_stop = 1;
                    break;
                }
                if (len == 0)
                    break;
                dp_engine_handle(buf, (size_t)len, af);
            }
        }

        if (s_dump) {
            s_dump = 0;
            dp_engine_stats_dump();
        }
    }

    close(kq);
    dp_ui_stop();

    if (s_stop)
        LOGI("caught signal %d, shutting down", (int)s_stop);
    dp_engine_stats_dump();
    return 0;
}

int main(int argc, char **argv)
{
    dp_log_init(false, DP_INFO);
    dp_config_defaults(&g_cfg);

    int rc = dp_cli_parse(argc, argv, &g_cfg);
    if (rc == 1)
        return 0;
    if (rc != 0)
        return 1;

    if (g_cfg.use_syslog)
        dp_log_init(true, dp_log_level());

    if (geteuid() != 0) {
        LOGE("dpiOS needs root: it creates a utun interface, loads pf rules "
             "and opens a BPF device. Try: sudo %s ...", argv[0]);
        return 1;
    }

    if (g_cfg.action == DP_ACTION_UNLOAD) {
        LOGI("flushing any leftover dpiOS pf rules");
        const char *argv_flush[] = { "/sbin/pfctl", "-a", DPIOS_ANCHOR,
                                     "-F", "all", NULL };
        int frc = dp_run(argv_flush);
        if (frc != 0) {
            LOGE("pfctl exited with %d", frc);
            return 1;
        }
        LOGI("anchor %s is clear", DPIOS_ANCHOR);
        return 0;
    }

    if (g_cfg.action == DP_ACTION_CHECK)
        return dp_selftest(&g_cfg);

    dp_config_dump(&g_cfg);

    if (g_cfg.blacklist_path[0])
        dp_list_load(g_cfg.blacklist_path, false);
    if (g_cfg.whitelist_path[0])
        dp_list_load(g_cfg.whitelist_path, true);

    atexit(cleanup);
    install_signals();

    if (!dp_net_discover(&g_net, g_cfg.iface)) {
        LOGE("network discovery failed");
        return 1;
    }

    if (!dp_utun_open(&s_tun, g_net.egress.mtu, g_cfg.enable_ipv6)) {
        LOGE("could not create the tunnel interface");
        return 1;
    }

    if (!dp_pf_enable()) {
        cleanup();
        return 1;
    }

    if (!dp_pf_anchor_reachable()) {
        LOGW("the system ruleset does not contain anchor \"com.apple/*\", so "
             "dpiOS rules will never be evaluated.");
        LOGW("load the stock ruleset once with: sudo pfctl -f /etc/pf.conf");
    }

    if (!dp_pf_load_rules(&g_cfg, &s_tun, &g_net)) {
        cleanup();
        return 1;
    }

    if (!dp_inject_init(&g_cfg, &g_net)) {
        cleanup();
        return 1;
    }

    if (g_cfg.auto_ttl)
        dp_monitor_start(&g_net);

    dp_engine_init(&g_cfg);

    if (g_cfg.doh && !dp_dns_start(&g_cfg)) {
        LOGE("the DoH resolver could not start; refusing to run with"
             " DNS still hijacked");
        cleanup();
        return 1;
    }

    dp_ui_start(&g_cfg, &g_net, &s_tun);

    int r = run_loop();

    cleanup();
    return r;
}
