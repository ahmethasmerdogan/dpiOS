/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
#include "dpios.h"

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

/*
 * 198.18.0.0/15 is reserved for benchmarking (RFC 2544) and is essentially
 * never routed, which makes it a safe home for the point-to-point link that
 * pf hands diverted packets to.
 */
#define DPIOS_UTUN_LOCAL  "198.18.222.1"
#define DPIOS_UTUN_PEER   "198.18.222.2"
#define DPIOS_UTUN_LOCAL6 "fd7a:d910:dp10::1"
#define DPIOS_UTUN_PEER6  "fd7a:d910:dp10::2"

static bool ifconfig_up(const char *ifname, int mtu)
{
    char mtus[16];
    snprintf(mtus, sizeof(mtus), "%d", mtu);

    const char *argv[] = { "/sbin/ifconfig", ifname, "inet",
                           DPIOS_UTUN_LOCAL, DPIOS_UTUN_PEER,
                           "mtu", mtus, "up", NULL };
    int rc = dp_run(argv);
    if (rc != 0) {
        LOGE("ifconfig %s failed (exit %d)", ifname, rc);
        return false;
    }
    return true;
}

static bool ifconfig_up6(const char *ifname)
{
    const char *argv[] = { "/sbin/ifconfig", ifname, "inet6",
                           DPIOS_UTUN_LOCAL6, DPIOS_UTUN_PEER6,
                           "prefixlen", "128", "up", NULL };
    int rc = dp_run(argv);
    if (rc != 0) {
        LOGW("ifconfig %s inet6 failed (exit %d) - IPv6 diversion disabled",
             ifname, rc);
        return false;
    }
    return true;
}

/*
 * sc_unit 0 asks the kernel for the first free utun. If that is refused we
 * probe units by hand - and each attempt gets a fresh socket, because a
 * kernel control socket that failed to connect is not reliably reusable.
 */
static int utun_attach(void)
{
    int last_errno = ENODEV;

    for (int unit = 0; unit <= 32; unit++) {
        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            LOGE("socket(PF_SYSTEM) failed: %s (are you root?)", strerror(errno));
            return -1;
        }

        struct ctl_info info;
        memset(&info, 0, sizeof(info));
        strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
        if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
            LOGE("CTLIOCGINFO failed: %s", strerror(errno));
            close(fd);
            return -1;
        }

        struct sockaddr_ctl sc;
        memset(&sc, 0, sizeof(sc));
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_id = info.ctl_id;
        sc.sc_unit = (u_int32_t)unit;

        if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == 0)
            return fd;

        last_errno = errno;
        LOGD("utun unit %d unavailable: %s", unit, strerror(errno));
        close(fd);
    }

    LOGE("could not attach to any utun unit: %s", strerror(last_errno));
    return -1;
}

bool dp_utun_open(dp_utun_t *t, int mtu, bool want_ipv6)
{
    memset(t, 0, sizeof(*t));
    t->fd = -1;

    int fd = utun_attach();
    if (fd < 0)
        return false;

    socklen_t namelen = sizeof(t->name);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
                   t->name, &namelen) < 0) {
        LOGE("UTUN_OPT_IFNAME failed: %s", strerror(errno));
        close(fd);
        return false;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    t->fd = fd;
    t->mtu = mtu;
    strlcpy(t->local_ip, DPIOS_UTUN_LOCAL, sizeof(t->local_ip));
    strlcpy(t->peer_ip, DPIOS_UTUN_PEER, sizeof(t->peer_ip));

    if (!ifconfig_up(t->name, mtu)) {
        dp_utun_close(t);
        return false;
    }
    if (want_ipv6 && ifconfig_up6(t->name))
        strlcpy(t->peer_ip6, DPIOS_UTUN_PEER6, sizeof(t->peer_ip6));

    LOGI("created %s (%s -> %s, mtu %d)", t->name, t->local_ip, t->peer_ip, mtu);
    return true;
}

void dp_utun_close(dp_utun_t *t)
{
    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
        LOGD("closed utun %s", t->name);
    }
}

/*
 * utun frames carry a 4 byte big-endian address family in front of the IP
 * header. Strip it and report the family separately.
 */
ssize_t dp_utun_read(dp_utun_t *t, uint8_t *buf, size_t buflen, int *af_out)
{
    uint8_t hdr[4];
    struct iovec iov[2] = {
        { .iov_base = hdr, .iov_len = sizeof(hdr) },
        { .iov_base = buf, .iov_len = buflen }
    };

    ssize_t n = readv(t->fd, iov, 2);
    if (n < 0)
        return -1;
    if (n < 4) {
        errno = EIO;
        return -1;
    }

    uint32_t af;
    memcpy(&af, hdr, 4);
    *af_out = (int)ntohl(af);
    return n - 4;
}
