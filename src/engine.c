#include "dpios.h"

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

dp_stats_t g_stats;

static const dp_config_t *s_cfg;
static uint8_t s_out[DPIOS_MAX_PACKET];   /* the packet being injected     */
static uint8_t s_work[DPIOS_MAX_PACKET];  /* rewritten HTTP payload        */
static uint8_t s_frag[DPIOS_MAX_PACKET];  /* intact datagram before IP frag */
static uint8_t s_fake[2048];

typedef struct {
    uint8_t *pkt;
    size_t   len;
    int      af;
    size_t   iphl;      /* bytes of IP header (incl. v6 extension headers) */
    uint8_t *tcp;
    size_t   thl;       /* bytes of TCP header including options */
    uint8_t *payload;
    size_t   plen;
    uint32_t seq;
    uint16_t sport;
    uint16_t dport;
    uint8_t  flags;
    int      mtu;
} pktinfo_t;

void dp_engine_init(const dp_config_t *c)
{
    s_cfg = c;
    memset(&g_stats, 0, sizeof(g_stats));
}

/* ------------------------------------------------------------------ parse */

static bool parse_packet(uint8_t *pkt, size_t len, int af, pktinfo_t *p)
{
    memset(p, 0, sizeof(*p));
    p->pkt = pkt;
    p->len = len;
    p->af = af;
    p->mtu = g_net.egress.mtu > 0 ? g_net.egress.mtu : 1500;

    if (af == AF_INET) {
        if (len < sizeof(struct ip))
            return false;
        struct ip *ip = (struct ip *)pkt;
        if (ip->ip_v != 4)
            return false;

        size_t iphl = (size_t)ip->ip_hl * 4;
        if (iphl < sizeof(struct ip) || iphl > len)
            return false;

        /* a non-leading fragment has no transport header to look at */
        if ((ntohs(ip->ip_off) & IP_OFFMASK) != 0)
            return false;
        if (ip->ip_p != IPPROTO_TCP)
            return false;

        p->iphl = iphl;
    } else if (af == AF_INET6) {
        if (len < sizeof(struct ip6_hdr))
            return false;
        struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt;
        if ((ip6->ip6_vfc & 0xf0) != 0x60)
            return false;
        if (ip6->ip6_nxt != IPPROTO_TCP)
            return false;    /* extension headers: pass through untouched */
        p->iphl = sizeof(struct ip6_hdr);
    } else {
        return false;
    }

    if (p->iphl + sizeof(struct tcphdr) > len)
        return false;

    p->tcp = pkt + p->iphl;
    struct tcphdr *th = (struct tcphdr *)p->tcp;
    size_t thl = (size_t)th->th_off * 4;
    if (thl < sizeof(struct tcphdr) || p->iphl + thl > len)
        return false;

    p->thl = thl;
    p->payload = p->tcp + thl;
    p->plen = len - p->iphl - thl;
    p->seq = ntohl(th->th_seq);
    p->sport = ntohs(th->th_sport);
    p->dport = ntohs(th->th_dport);
    p->flags = th->th_flags;
    return true;
}

static void set_ip_length(pktinfo_t *p, uint8_t *buf, size_t total)
{
    if (p->af == AF_INET) {
        struct ip *ip = (struct ip *)buf;
        ip->ip_len = htons((uint16_t)total);
    } else {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
        ip6->ip6_plen = htons((uint16_t)(total - p->iphl));
    }
}

static void set_ttl(pktinfo_t *p, uint8_t *buf, int ttl)
{
    if (ttl <= 0)
        return;
    if (p->af == AF_INET)
        ((struct ip *)buf)->ip_ttl = (uint8_t)ttl;
    else
        ((struct ip6_hdr *)buf)->ip6_hlim = (uint8_t)ttl;
}

/* ------------------------------------------------------------------ emit */

/*
 * Build and inject one TCP segment carrying `payload`. Everything except the
 * payload, sequence number, TTL and PSH bit is inherited from the packet the
 * kernel handed us, so options like timestamps and window scale survive.
 *
 * Payloads larger than the path MTU are re-segmented rather than dropped;
 * that only happens if the stack hands us an offloaded jumbo segment.
 */
static bool emit_tcp(pktinfo_t *p, const uint8_t *payload, size_t plen,
                     uint32_t seq, int ttl, bool psh, bool corrupt_cksum)
{
    size_t hdr = p->iphl + p->thl;
    size_t max_seg = (size_t)p->mtu > hdr + 8 ? (size_t)p->mtu - hdr : 536;
    bool ok = true;
    size_t done = 0;

    do {
        size_t chunk = plen - done;
        if (chunk > max_seg)
            chunk = max_seg;

        size_t total = hdr + chunk;
        if (total > sizeof(s_out))
            return false;

        memcpy(s_out, p->pkt, hdr);
        if (chunk)
            memcpy(s_out + hdr, payload + done, chunk);

        struct tcphdr *th = (struct tcphdr *)(s_out + p->iphl);
        th->th_seq = htonl(seq + (uint32_t)done);

        bool last = (done + chunk >= plen);
        if (psh && last)
            th->th_flags |= TH_PUSH;
        else
            th->th_flags &= (uint8_t)~TH_PUSH;

        set_ip_length(p, s_out, total);
        set_ttl(p, s_out, ttl);
        dp_fix_checksums(s_out, total, p->af);

        if (corrupt_cksum) {
            /* flip enough bits that no valid packet can share the value */
            th->th_sum = (uint16_t)(th->th_sum ^ htons(0x5a5a));
            if (th->th_sum == 0)
                th->th_sum = htons(0x1234);
        }

        if (!dp_inject_packet(s_out, total, p->af))
            ok = false;

        done += chunk;
    } while (done < plen);

    return ok;
}

/*
 * IPv4-only alternative to TCP splitting: keep one TCP segment but chop it
 * into two IP fragments. Some middleboxes reassemble TCP but not IP.
 */
static bool emit_ip_fragmented(pktinfo_t *p, size_t split)
{
    if (p->af != AF_INET)
        return emit_tcp(p, p->payload, p->plen, p->seq, 0, true, false);

    size_t body = p->thl + p->plen;
    size_t first = p->thl + split;
    first &= ~(size_t)7;                    /* fragment offsets count 8s */
    if (first == 0 || first >= body)
        return emit_tcp(p, p->payload, p->plen, p->seq, 0, true, false);

    size_t total = p->iphl + body;
    if (total > sizeof(s_frag))
        return emit_tcp(p, p->payload, p->plen, p->seq, 0, true, false);

    /*
     * Rebuild the datagram from the current payload - which for HTTP is the
     * rewritten copy, not what arrived - and checksum it while it is still
     * intact. Only then is it cut into fragments.
     */
    memcpy(s_frag, p->pkt, p->iphl + p->thl);
    memcpy(s_frag + p->iphl + p->thl, p->payload, p->plen);
    ((struct ip *)s_frag)->ip_len = htons((uint16_t)total);
    dp_fix_checksums(s_frag, total, AF_INET);

    struct ip *ip = (struct ip *)s_out;
    bool ok = true;

    memcpy(s_out, s_frag, p->iphl + first);
    ip->ip_len = htons((uint16_t)(p->iphl + first));
    ip->ip_off = htons((uint16_t)IP_MF);
    ip->ip_sum = 0;
    ip->ip_sum = htons(dp_cksum_finish(dp_cksum_partial(s_out, p->iphl, 0)));
    if (!dp_inject_packet(s_out, p->iphl + first, AF_INET))
        ok = false;

    size_t rest = body - first;
    memcpy(s_out, s_frag, p->iphl);
    memcpy(s_out + p->iphl, s_frag + p->iphl + first, rest);
    ip->ip_len = htons((uint16_t)(p->iphl + rest));
    ip->ip_off = htons((uint16_t)(first / 8));
    ip->ip_sum = 0;
    ip->ip_sum = htons(dp_cksum_finish(dp_cksum_partial(s_out, p->iphl, 0)));
    if (!dp_inject_packet(s_out, p->iphl + rest, AF_INET))
        ok = false;

    g_stats.frags_sent += 2;
    return ok;
}

static bool emit_split(pktinfo_t *p, size_t split)
{
    if (split == 0 || split >= p->plen) {
        return emit_tcp(p, p->payload, p->plen, p->seq, 0, true, false);
    }

    if (s_cfg->ip_frag)
        return emit_ip_fragmented(p, split);

    bool ok = true;
    if (s_cfg->reverse_frag) {
        /*
         * Tail first. A DPI engine that keys off the first segment it sees
         * never gets a coherent view of the request; the receiving stack
         * reorders it without complaint.
         */
        ok &= emit_tcp(p, p->payload + split, p->plen - split,
                       p->seq + (uint32_t)split, 0, true, false);
        ok &= emit_tcp(p, p->payload, split, p->seq, 0, false, false);
    } else {
        ok &= emit_tcp(p, p->payload, split, p->seq, 0, false, false);
        ok &= emit_tcp(p, p->payload + split, p->plen - split,
                       p->seq + (uint32_t)split, 0, true, false);
    }

    g_stats.frags_sent += 2;
    return ok;
}

/* ------------------------------------------------------------------ fakes */

static int pick_fake_ttl(pktinfo_t *p)
{
    if (!s_cfg->auto_ttl)
        return s_cfg->fake_ttl;

    int hops = -1;
    if (p->af == AF_INET) {
        const struct ip *ip = (const struct ip *)p->pkt;
        hops = dp_monitor_hops(&ip->ip_dst, AF_INET);
    }

    int ttl;
    if (hops > 0) {
        ttl = hops - s_cfg->auto_ttl_delta;
    } else {
        ttl = (s_cfg->auto_ttl_min + s_cfg->auto_ttl_max) / 2;
    }

    if (ttl < s_cfg->auto_ttl_min)
        ttl = s_cfg->auto_ttl_min;
    if (ttl > s_cfg->auto_ttl_max)
        ttl = s_cfg->auto_ttl_max;
    return ttl;
}

/*
 * The decoy: a well-formed but doomed copy of the request. It reaches the DPI
 * box, which latches onto its harmless hostname, and then dies before the
 * server ever sees it - either because the TTL runs out, the checksum is
 * broken, or the sequence number is far outside the window.
 */
static void send_fakes(pktinfo_t *p, bool is_tls, size_t real_len)
{
    if (!s_cfg->fake_enable)
        return;

    size_t flen;
    if (is_tls)
        flen = dp_tls_build_fake_hello(s_fake, sizeof(s_fake),
                                       s_cfg->fake_sni, real_len);
    else
        flen = dp_http_build_fake(s_fake, sizeof(s_fake),
                                  s_cfg->fake_sni, real_len);
    if (flen == 0)
        return;

    int ttl = pick_fake_ttl(p);
    uint32_t seq = p->seq;
    if (s_cfg->wrong_seq)
        seq = p->seq - s_cfg->wrong_seq_delta;

    int rounds = s_cfg->fake_resend > 0 ? s_cfg->fake_resend : 1;
    for (int i = 0; i < rounds; i++) {
        if (emit_tcp(p, s_fake, flen, seq, ttl, true, s_cfg->wrong_chksum))
            g_stats.fakes_sent++;
    }
}

/* ----------------------------------------------------------------- handle */

static void passthrough(pktinfo_t *p)
{
    g_stats.passthrough++;
    memcpy(s_out, p->pkt, p->len);
    dp_fix_checksums(s_out, p->len, p->af);
    dp_inject_packet(s_out, p->len, p->af);
}

/* Forward a packet we could not even parse, exactly as it arrived. */
static void passthrough_raw(uint8_t *pkt, size_t len, int af)
{
    g_stats.passthrough++;
    memcpy(s_out, pkt, len);
    dp_fix_checksums(s_out, len, af);
    dp_inject_packet(s_out, len, af);
}

static size_t clamp_split(size_t want, size_t plen)
{
    if (plen < 2)
        return 0;
    if (want == 0)
        return 0;
    if (want >= plen)
        return plen - 1;
    return want;
}

void dp_engine_handle(uint8_t *pkt, size_t len, int af)
{
    g_stats.seen++;

    pktinfo_t p;
    if (!parse_packet(pkt, len, af, &p)) {
        passthrough_raw(pkt, len, af);
        return;
    }

    if (p.plen == 0 || !dp_config_has_port(s_cfg, p.dport)) {
        passthrough(&p);
        return;
    }

    if (s_cfg->max_payload > 0 && p.plen > (size_t)s_cfg->max_payload) {
        g_stats.oversized++;
        passthrough(&p);
        return;
    }

    dp_tls_info_t tls;
    dp_http_info_t http;
    bool is_tls = dp_tls_parse(p.payload, p.plen, &tls) && tls.is_client_hello;
    bool is_http = !is_tls && dp_http_parse(p.payload, p.plen, &http);

    if (!is_tls && !is_http) {
        passthrough(&p);
        return;
    }

    const char *host = is_tls ? tls.sni : http.host;

    if (!dp_list_should_process(host)) {
        g_stats.skipped_list++;
        LOGT("skipping %s (list)", host[0] ? host : "<no host>");
        passthrough(&p);
        return;
    }

    if (s_cfg->dry_run) {
        LOGI("[dry-run] would process %s request to %s",
             is_tls ? "TLS" : "HTTP", host[0] ? host : "<unknown>");
        passthrough(&p);
        return;
    }

    size_t split;

    if (is_tls) {
        g_stats.tls_hits++;
        if (s_cfg->frag_sni && tls.sni_len > 1)
            split = tls.sni_offset + tls.sni_len / 2;
        else
            split = (size_t)s_cfg->frag_https;
        LOGD("TLS ClientHello -> %s (%zu bytes, split at %zu)",
             host[0] ? host : "<no sni>", p.plen, split);
    } else {
        g_stats.http_hits++;
        /*
         * Header rewriting happens on a scratch copy and never changes the
         * payload length - the kernel already committed to these sequence
         * numbers, so a byte more or less would desynchronise the stream.
         */
        memcpy(s_work, p.payload, p.plen);
        dp_http_mangle(s_work, p.plen, sizeof(s_work), &http, s_cfg);
        p.payload = s_work;

        if (s_cfg->frag_sni && http.host_value_len > 1)
            split = http.host_value_off + http.host_value_len / 2;
        else
            split = (size_t)(s_cfg->frag_http ? s_cfg->frag_http
                                              : s_cfg->frag_persistent);
        LOGD("HTTP request -> %s (%zu bytes, split at %zu)",
             host[0] ? host : "<no host>", p.plen, split);
    }

    split = clamp_split(split, p.plen);

    send_fakes(&p, is_tls, p.plen);
    emit_split(&p, split);
}

void dp_engine_stats_dump(void)
{
    LOGI("packets seen %llu | passthrough %llu | http %llu | tls %llu | "
         "fakes %llu | fragments %llu | list-skipped %llu | oversized %llu",
         (unsigned long long)g_stats.seen,
         (unsigned long long)g_stats.passthrough,
         (unsigned long long)g_stats.http_hits,
         (unsigned long long)g_stats.tls_hits,
         (unsigned long long)g_stats.fakes_sent,
         (unsigned long long)g_stats.frags_sent,
         (unsigned long long)g_stats.skipped_list,
         (unsigned long long)g_stats.oversized);
    LOGI("injected %llu packets, %llu injection errors",
         (unsigned long long)dp_inject_count(),
         (unsigned long long)dp_inject_errors());
}
