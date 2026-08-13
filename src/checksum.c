#include "dpios.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

uint32_t dp_cksum_partial(const void *data, size_t len, uint32_t sum)
{
    const uint8_t *p = (const uint8_t *)data;

    while (len > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint32_t)(p[0] << 8);

    return sum;
}

uint16_t dp_cksum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/*
 * Packets handed to us over utun may carry a bogus or offloaded checksum, and
 * anything we inject through BPF bypasses the NIC's offload engine entirely.
 * So every packet leaving dpiOS gets its checksums recomputed from scratch.
 */
void dp_fix_checksums_v4(uint8_t *pkt, size_t len)
{
    if (len < sizeof(struct ip))
        return;

    struct ip *ip = (struct ip *)pkt;
    size_t ihl = (size_t)ip->ip_hl * 4;
    if (ihl < sizeof(struct ip) || ihl > len)
        return;

    ip->ip_sum = 0;
    ip->ip_sum = htons(dp_cksum_finish(dp_cksum_partial(pkt, ihl, 0)));

    /* Only the first fragment carries a usable transport header. */
    if ((ntohs(ip->ip_off) & IP_OFFMASK) != 0)
        return;

    size_t plen = len - ihl;
    uint32_t sum = 0;
    sum = dp_cksum_partial(&ip->ip_src, 4, sum);
    sum = dp_cksum_partial(&ip->ip_dst, 4, sum);
    sum += (uint32_t)ip->ip_p;
    sum += (uint32_t)plen;

    if (ip->ip_p == IPPROTO_TCP && plen >= sizeof(struct tcphdr)) {
        struct tcphdr *th = (struct tcphdr *)(pkt + ihl);
        th->th_sum = 0;
        th->th_sum = htons(dp_cksum_finish(dp_cksum_partial(th, plen, sum)));
    } else if (ip->ip_p == IPPROTO_UDP && plen >= sizeof(struct udphdr)) {
        struct udphdr *uh = (struct udphdr *)(pkt + ihl);
        uh->uh_sum = 0;
        uint16_t c = htons(dp_cksum_finish(dp_cksum_partial(uh, plen, sum)));
        uh->uh_sum = (c == 0) ? 0xffff : c;
    }
}

void dp_fix_checksums_v6(uint8_t *pkt, size_t len)
{
    if (len < sizeof(struct ip6_hdr))
        return;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
    size_t off = sizeof(struct ip6_hdr);
    uint8_t next = ip6->ip6_nxt;

    /* Walk the handful of extension headers we might realistically see. */
    while (off < len) {
        if (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING ||
            next == IPPROTO_DSTOPTS) {
            if (off + 2 > len)
                return;
            uint8_t nxt = pkt[off];
            size_t hlen = ((size_t)pkt[off + 1] + 1) * 8;
            off += hlen;
            next = nxt;
            continue;
        }
        break;
    }
    if (off > len)
        return;

    size_t plen = len - off;
    uint32_t sum = 0;
    sum = dp_cksum_partial(&ip6->ip6_src, 16, sum);
    sum = dp_cksum_partial(&ip6->ip6_dst, 16, sum);
    sum += (uint32_t)plen;
    sum += (uint32_t)next;

    if (next == IPPROTO_TCP && plen >= sizeof(struct tcphdr)) {
        struct tcphdr *th = (struct tcphdr *)(pkt + off);
        th->th_sum = 0;
        th->th_sum = htons(dp_cksum_finish(dp_cksum_partial(th, plen, sum)));
    } else if (next == IPPROTO_UDP && plen >= sizeof(struct udphdr)) {
        struct udphdr *uh = (struct udphdr *)(pkt + off);
        uh->uh_sum = 0;
        uint16_t c = htons(dp_cksum_finish(dp_cksum_partial(uh, plen, sum)));
        uh->uh_sum = (c == 0) ? 0xffff : c;
    }
}

void dp_fix_checksums(uint8_t *pkt, size_t len, int af)
{
    if (af == AF_INET6)
        dp_fix_checksums_v6(pkt, len);
    else
        dp_fix_checksums_v4(pkt, len);
}
