/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
#include "dpios.h"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define ETH_HDR_LEN     14
#define ETHERTYPE_IP4   0x0800
#define ETHERTYPE_IP6   0x86dd
#define DPIOS_TOS_MARK  0x04    /* only used by the raw-socket fallback */

static int      s_bpf = -1;
static int      s_raw4 = -1;
static const dp_netinfo_t *s_ni = NULL;
static dp_inject_mode_t s_mode = INJECT_BPF;
static uint64_t s_sent = 0;
static uint64_t s_errs = 0;
static uint64_t s_last_refresh_at = 0;
static uint8_t  s_frame[ETH_HDR_LEN + DPIOS_MAX_PACKET];

uint64_t dp_inject_count(void) { return s_sent; }
uint64_t dp_inject_errors(void) { return s_errs; }

static bool bpf_open(const char *ifname)
{
    char path[32];
    int fd = -1;

    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        fd = open(path, O_RDWR);
        if (fd >= 0)
            break;
        if (errno != EBUSY && errno != EACCES && errno != ENOENT) {
            LOGD("open %s: %s", path, strerror(errno));
        }
    }
    if (fd < 0) {
        LOGE("no free /dev/bpf device (need root, and no other sniffer hogging "
             "every node)");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        LOGE("BIOCSETIF(%s) failed: %s", ifname, strerror(errno));
        close(fd);
        return false;
    }

    /* we supply the whole link layer header ourselves */
    u_int on = 1;
    if (ioctl(fd, BIOCSHDRCMPLT, &on) < 0) {
        LOGE("BIOCSHDRCMPLT failed: %s", strerror(errno));
        close(fd);
        return false;
    }

    /* injected frames must not come back to us through this same descriptor */
    u_int seesent = 0;
    ioctl(fd, BIOCSSEESENT, &seesent);

    u_int dlt = 0;
    if (ioctl(fd, BIOCGDLT, &dlt) == 0 && dlt != DLT_EN10MB) {
        LOGE("%s has link type %u, not ethernet - BPF injection needs an "
             "ethernet-style interface (try --inject raw)", ifname, dlt);
        close(fd);
        return false;
    }

    s_bpf = fd;
    LOGI("BPF injector attached to %s via %s", ifname, path);
    return true;
}

static bool raw_open(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        LOGE("socket(SOCK_RAW) failed: %s", strerror(errno));
        return false;
    }

    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        LOGE("IP_HDRINCL failed: %s", strerror(errno));
        close(fd);
        return false;
    }

    s_raw4 = fd;
    LOGI("raw socket injector ready (packets marked tos 0x%02x to avoid a "
         "routing loop)", DPIOS_TOS_MARK);
    return true;
}

bool dp_inject_init(const dp_config_t *c, const dp_netinfo_t *ni)
{
    s_ni = ni;
    s_mode = c->inject_mode;

    if (s_mode == INJECT_BPF) {
        if (!ni->egress.has_mac) {
            LOGE("%s has no ethernet address; use --inject raw",
                 ni->egress.name);
            return false;
        }
        if (!ni->has_gw_mac) {
            LOGE("gateway hardware address is unknown, cannot build ethernet "
                 "frames. Ping the gateway once and retry, or use --inject raw");
            return false;
        }
        return bpf_open(ni->egress.name);
    }

    return raw_open();
}

void dp_inject_close(void)
{
    if (s_bpf >= 0) { close(s_bpf); s_bpf = -1; }
    if (s_raw4 >= 0) { close(s_raw4); s_raw4 = -1; }
}

/*
 * Everything we divert is destined for the open internet (pf skips RFC1918 and
 * friends), so the next hop is always the default gateway. The on-link case is
 * still handled for the odd public address sitting on the same segment.
 */
static const uint8_t *next_hop_mac(const uint8_t *pkt, int af)
{
    static uint8_t cached[6];

    if (af == AF_INET && s_ni->egress.has_addr4 && s_ni->egress.mask4.s_addr) {
        const struct ip *ip = (const struct ip *)pkt;
        uint32_t mask = s_ni->egress.mask4.s_addr;
        if ((ip->ip_dst.s_addr & mask) == (s_ni->egress.addr4.s_addr & mask) &&
            ip->ip_dst.s_addr != s_ni->gw4.s_addr) {
            if (dp_net_lookup_mac(AF_INET, &ip->ip_dst, cached))
                return cached;
        }
    }

    if (af == AF_INET6)
        return s_ni->has_gw6_mac ? s_ni->gw6_mac : s_ni->gw_mac;

    return s_ni->gw_mac;
}

static bool inject_bpf(const uint8_t *pkt, size_t len, int af)
{
    if (len + ETH_HDR_LEN > sizeof(s_frame)) {
        LOGD("packet too large for injection (%zu bytes)", len);
        s_errs++;
        return false;
    }

    const uint8_t *dmac = next_hop_mac(pkt, af);
    uint16_t etype = (af == AF_INET6) ? ETHERTYPE_IP6 : ETHERTYPE_IP4;

    memcpy(s_frame, dmac, 6);
    memcpy(s_frame + 6, s_ni->egress.mac, 6);
    s_frame[12] = (uint8_t)(etype >> 8);
    s_frame[13] = (uint8_t)(etype & 0xff);
    memcpy(s_frame + ETH_HDR_LEN, pkt, len);

    ssize_t w = write(s_bpf, s_frame, len + ETH_HDR_LEN);
    if (w < 0) {
        /*
         * ENETDOWN / EHOSTDOWN show up when the link flaps - roaming between
         * Wi-Fi networks, waking from sleep. The gateway's hardware address is
         * usually what went stale, so re-resolve it, but not on every packet.
         */
        s_errs++;
        if (errno == ENETDOWN || errno == EHOSTDOWN || errno == ENXIO ||
            errno == EINVAL) {
            if (s_errs - s_last_refresh_at > 32) {
                s_last_refresh_at = s_errs;
                LOGW("BPF write failed (%s) - re-resolving the gateway",
                     strerror(errno));
                dp_net_refresh_gw_mac(&g_net);
            }
        } else {
            LOGD("BPF write failed: %s", strerror(errno));
        }
        return false;
    }

    s_sent++;
    return true;
}

static bool inject_raw(const uint8_t *pkt, size_t len, int af)
{
    if (af != AF_INET) {
        LOGD("raw injection mode is IPv4 only, dropping an IPv6 packet");
        s_errs++;
        return false;
    }
    if (len < sizeof(struct ip) || len > sizeof(s_frame))
        return false;

    memcpy(s_frame, pkt, len);
    struct ip *ip = (struct ip *)s_frame;

    /* mark it so our own pf rule lets it out instead of diverting it again */
    ip->ip_tos = (uint8_t)(ip->ip_tos | DPIOS_TOS_MARK);
    ip->ip_sum = 0;
    ip->ip_sum = htons(dp_cksum_finish(
        dp_cksum_partial(s_frame, (size_t)ip->ip_hl * 4, 0)));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->ip_dst;

    /*
     * Darwin's IP_HDRINCL path expects ip_len and ip_off in host byte order.
     * Convert on the copy, right before handing it to the kernel.
     */
    uint16_t saved_len = ip->ip_len;
    uint16_t saved_off = ip->ip_off;
    ip->ip_len = ntohs(saved_len);
    ip->ip_off = ntohs(saved_off);

    ssize_t w = sendto(s_raw4, s_frame, len, 0,
                       (struct sockaddr *)&dst, sizeof(dst));
    if (w < 0) {
        LOGD("raw sendto failed: %s", strerror(errno));
        s_errs++;
        return false;
    }

    s_sent++;
    return true;
}

bool dp_inject_packet(const uint8_t *pkt, size_t len, int af)
{
    if (!pkt || len == 0)
        return false;
    return (s_mode == INJECT_BPF) ? inject_bpf(pkt, len, af)
                                  : inject_raw(pkt, len, af);
}
