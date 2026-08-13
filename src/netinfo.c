#include "dpios.h"

#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <unistd.h>

dp_netinfo_t g_net;

const char *dp_mac_str(const uint8_t mac[6], char *buf, size_t buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

/* Round a sockaddr length up the way the routing socket lays them out. */
#define RT_ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static void rt_unpack(int addrs, struct sockaddr *sa, struct sockaddr **out)
{
    for (int i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            out[i] = sa;
            sa = (struct sockaddr *)((char *)sa + RT_ROUNDUP(sa->sa_len));
        } else {
            out[i] = NULL;
        }
    }
}

/*
 * mib[4] selects the operation (dump the table, or dump entries matching a
 * flag) and mib[5] carries the flag itself - that is how arp(8) and ndp(8)
 * reach the link-layer cache.
 */
static uint8_t *sysctl_route_dump(int family, int op, int flags, size_t *lenp)
{
    int mib[6] = { CTL_NET, PF_ROUTE, 0, family, op, flags };
    size_t need = 0;

    if (sysctl(mib, 6, NULL, &need, NULL, 0) < 0) {
        LOGD("sysctl(route sizing) failed: %s", strerror(errno));
        return NULL;
    }
    if (need == 0)
        return NULL;

    /* The table can grow between the sizing call and the fetch. */
    need += need / 4 + 4096;
    uint8_t *buf = malloc(need);
    if (!buf)
        return NULL;

    if (sysctl(mib, 6, buf, &need, NULL, 0) < 0) {
        LOGD("sysctl(route fetch) failed: %s", strerror(errno));
        free(buf);
        return NULL;
    }
    *lenp = need;
    return buf;
}

/* Locate the default route and record its gateway + interface. */
static bool find_default_route(dp_netinfo_t *ni, int af, char *ifname, size_t ifname_len)
{
    size_t len = 0;
    uint8_t *buf = sysctl_route_dump(af, NET_RT_DUMP, 0, &len);
    if (!buf)
        return false;

    bool found = false;
    for (uint8_t *p = buf; p + sizeof(struct rt_msghdr) <= buf + len;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)p;
        if (rtm->rtm_msglen == 0 || p + rtm->rtm_msglen > buf + len)
            break;

        struct sockaddr *addrs[RTAX_MAX];
        rt_unpack(rtm->rtm_addrs, (struct sockaddr *)(rtm + 1), addrs);

        bool is_default = (rtm->rtm_flags & RTF_GATEWAY) &&
                          addrs[RTAX_DST] && addrs[RTAX_GATEWAY];

        if (is_default && af == AF_INET && addrs[RTAX_DST]->sa_family == AF_INET) {
            struct sockaddr_in *dst = (struct sockaddr_in *)addrs[RTAX_DST];
            if (dst->sin_addr.s_addr == INADDR_ANY &&
                addrs[RTAX_GATEWAY]->sa_family == AF_INET) {
                ni->gw4 = ((struct sockaddr_in *)addrs[RTAX_GATEWAY])->sin_addr;
                ni->has_gw4 = true;
                if_indextoname((unsigned)rtm->rtm_index, ifname);
                (void)ifname_len;
                found = true;
                break;
            }
        } else if (is_default && af == AF_INET6 &&
                   addrs[RTAX_DST]->sa_family == AF_INET6) {
            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)addrs[RTAX_DST];
            if (IN6_IS_ADDR_UNSPECIFIED(&dst->sin6_addr) &&
                addrs[RTAX_GATEWAY]->sa_family == AF_INET6) {
                ni->gw6 = ((struct sockaddr_in6 *)addrs[RTAX_GATEWAY])->sin6_addr;
                ni->has_gw6 = true;
                if (ifname[0] == '\0')
                    if_indextoname((unsigned)rtm->rtm_index, ifname);
                found = true;
                break;
            }
        }

        p += rtm->rtm_msglen;
    }

    free(buf);
    return found;
}

/* Pull a neighbour's link-layer address out of the ARP / NDP cache. */
bool dp_net_lookup_mac(int af, const void *target, uint8_t mac[6])
{
    size_t len = 0;
    uint8_t *buf = sysctl_route_dump(af, NET_RT_FLAGS, RTF_LLINFO, &len);
    if (!buf)
        return false;

    bool found = false;
    for (uint8_t *p = buf; p + sizeof(struct rt_msghdr) <= buf + len;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)p;
        if (rtm->rtm_msglen == 0 || p + rtm->rtm_msglen > buf + len)
            break;

        struct sockaddr *addrs[RTAX_MAX];
        rt_unpack(rtm->rtm_addrs, (struct sockaddr *)(rtm + 1), addrs);

        struct sockaddr *dst = addrs[RTAX_DST];
        struct sockaddr *gw = addrs[RTAX_GATEWAY];
        if (dst && gw && gw->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)gw;
            bool hit = false;
            if (af == AF_INET && dst->sa_family == AF_INET) {
                hit = memcmp(&((struct sockaddr_in *)dst)->sin_addr, target, 4) == 0;
            } else if (af == AF_INET6 && dst->sa_family == AF_INET6) {
                hit = memcmp(&((struct sockaddr_in6 *)dst)->sin6_addr, target, 16) == 0;
            }
            if (hit && sdl->sdl_alen == 6) {
                memcpy(mac, LLADDR(sdl), 6);
                found = true;
                break;
            }
        }

        p += rtm->rtm_msglen;
    }

    free(buf);
    return found;
}

/* Nudge the stack into resolving the gateway if the cache is cold. */
static void prime_neighbour(int af, const void *addr)
{
    int s = socket(af, SOCK_DGRAM, 0);
    if (s < 0)
        return;

    if (af == AF_INET) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_len = sizeof(sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(9);            /* discard */
        memcpy(&sin.sin_addr, addr, 4);
        sendto(s, "", 1, 0, (struct sockaddr *)&sin, sizeof(sin));
    } else {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        sin6.sin6_len = sizeof(sin6);
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(9);
        memcpy(&sin6.sin6_addr, addr, 16);
        sendto(s, "", 1, 0, (struct sockaddr *)&sin6, sizeof(sin6));
    }
    close(s);
    usleep(150000);
}

static bool fill_iface(dp_iface_t *ifc, const char *name)
{
    memset(ifc, 0, sizeof(*ifc));
    strlcpy(ifc->name, name, sizeof(ifc->name));
    ifc->index = (int)if_nametoindex(name);
    ifc->mtu = 1500;

    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) {
        LOGE("getifaddrs failed: %s", strerror(errno));
        return false;
    }

    for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || strcmp(p->ifa_name, name) != 0)
            continue;

        if (p->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)p->ifa_addr;
            if (sdl->sdl_alen == 6) {
                memcpy(ifc->mac, LLADDR(sdl), 6);
                ifc->has_mac = true;
            }
        } else if (p->ifa_addr->sa_family == AF_INET && !ifc->has_addr4) {
            ifc->addr4 = ((struct sockaddr_in *)p->ifa_addr)->sin_addr;
            if (p->ifa_netmask && p->ifa_netmask->sa_family == AF_INET)
                ifc->mask4 = ((struct sockaddr_in *)p->ifa_netmask)->sin_addr;
            ifc->has_addr4 = true;
        } else if (p->ifa_addr->sa_family == AF_INET6) {
            struct in6_addr *a = &((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
            if (!IN6_IS_ADDR_LINKLOCAL(a) && !ifc->has_addr6) {
                ifc->addr6 = *a;
                ifc->has_addr6 = true;
            }
        }
    }
    freeifaddrs(ifa);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
        if (ioctl(s, SIOCGIFMTU, &ifr) == 0)
            ifc->mtu = ifr.ifr_mtu;
        close(s);
    }

    return ifc->index != 0;
}

bool dp_net_refresh_gw_mac(dp_netinfo_t *ni)
{
    bool ok = false;

    if (ni->has_gw4) {
        ni->has_gw_mac = dp_net_lookup_mac(AF_INET, &ni->gw4, ni->gw_mac);
        if (!ni->has_gw_mac) {
            prime_neighbour(AF_INET, &ni->gw4);
            ni->has_gw_mac = dp_net_lookup_mac(AF_INET, &ni->gw4, ni->gw_mac);
        }
        ok = ni->has_gw_mac;
    }

    if (ni->has_gw6) {
        ni->has_gw6_mac = dp_net_lookup_mac(AF_INET6, &ni->gw6, ni->gw6_mac);
        if (!ni->has_gw6_mac) {
            prime_neighbour(AF_INET6, &ni->gw6);
            ni->has_gw6_mac = dp_net_lookup_mac(AF_INET6, &ni->gw6, ni->gw6_mac);
        }
    }

    return ok;
}

bool dp_net_discover(dp_netinfo_t *ni, const char *forced_iface)
{
    memset(ni, 0, sizeof(*ni));

    char ifname[IFNAMSIZ];
    memset(ifname, 0, sizeof(ifname));

    if (forced_iface && *forced_iface) {
        strlcpy(ifname, forced_iface, sizeof(ifname));
        find_default_route(ni, AF_INET, ifname, sizeof(ifname));
        /* keep the forced name even if the default route lives elsewhere */
        strlcpy(ifname, forced_iface, sizeof(ifname));
    } else {
        if (!find_default_route(ni, AF_INET, ifname, sizeof(ifname))) {
            LOGE("no IPv4 default route found - is this machine online?");
            return false;
        }
    }

    find_default_route(ni, AF_INET6, ifname, sizeof(ifname));

    if (!fill_iface(&ni->egress, ifname)) {
        LOGE("cannot inspect egress interface '%s'", ifname);
        return false;
    }

    char mb[32];
    LOGI("egress interface: %s (index %d, mtu %d, mac %s)",
         ni->egress.name, ni->egress.index, ni->egress.mtu,
         ni->egress.has_mac ? dp_mac_str(ni->egress.mac, mb, sizeof(mb)) : "none");

    if (ni->has_gw4) {
        char gb[64];
        inet_ntop(AF_INET, &ni->gw4, gb, sizeof(gb));
        LOGI("default gateway: %s", gb);
    }

    if (!ni->egress.has_mac)
        LOGW("egress interface has no ethernet address - BPF injection will not "
             "work here, use --inject raw");

    dp_net_refresh_gw_mac(ni);
    if (ni->has_gw_mac) {
        char mb2[32];
        LOGI("gateway hwaddr: %s", dp_mac_str(ni->gw_mac, mb2, sizeof(mb2)));
    } else {
        LOGW("gateway hardware address unknown (ARP cache cold?)");
    }

    return true;
}
