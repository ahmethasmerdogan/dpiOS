/*
 * Passive TTL observer.
 *
 * With the route-to design the return traffic never passes through dpiOS - the
 * kernel handles it directly. That is good for throughput but it means we
 * cannot see how far away a server is, which --auto-ttl needs. So we tap the
 * egress interface read-only through a second BPF descriptor and note the TTL
 * of inbound packets per source address. Nothing is modified or delayed here.
 */
#include "dpios.h"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MON_BUFLEN   (256 * 1024)
#define MON_SLOTS    1024

typedef struct {
    uint32_t addr;
    uint8_t  ttl;
    bool     used;
} ttl_slot_t;

static int         s_fd = -1;
static uint8_t    *s_buf = NULL;
static size_t      s_buflen = 0;
static ttl_slot_t  s_slots[MON_SLOTS];

int dp_monitor_fd(void) { return s_fd; }

/* Accept IPv4 TCP only; everything else is filtered out in the kernel. */
static struct bpf_insn s_filter[] = {
    { BPF_LD  + BPF_H + BPF_ABS, 0, 0, 12 },        /* A = ethertype      */
    { BPF_JMP + BPF_JEQ + BPF_K, 0, 3, 0x0800 },    /* IPv4 ?             */
    { BPF_LD  + BPF_B + BPF_ABS, 0, 0, 23 },        /* A = ip_p           */
    { BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 6 },         /* TCP ?              */
    { BPF_RET + BPF_K,           0, 0, 128 },       /* keep the headers   */
    { BPF_RET + BPF_K,           0, 0, 0 },         /* drop               */
};

bool dp_monitor_start(const dp_netinfo_t *ni)
{
    char path[32];
    int fd = -1;

    for (int i = 0; i < 256; i++) {
        snprintf(path, sizeof(path), "/dev/bpf%d", i);
        fd = open(path, O_RDONLY);
        if (fd >= 0)
            break;
    }
    if (fd < 0) {
        LOGW("no free /dev/bpf for the TTL monitor - --auto-ttl will fall back "
             "to its default hop count");
        return false;
    }

    u_int blen = MON_BUFLEN;
    ioctl(fd, BIOCSBLEN, &blen);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ni->egress.name, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        LOGW("TTL monitor BIOCSETIF(%s) failed: %s",
             ni->egress.name, strerror(errno));
        close(fd);
        return false;
    }

    u_int on = 1;
    ioctl(fd, BIOCIMMEDIATE, &on);
    u_int seesent = 0;
    ioctl(fd, BIOCSSEESENT, &seesent);      /* inbound packets only */

    struct bpf_program prog;
    prog.bf_len = (u_int)(sizeof(s_filter) / sizeof(s_filter[0]));
    prog.bf_insns = s_filter;
    if (ioctl(fd, BIOCSETF, &prog) < 0)
        LOGD("TTL monitor filter rejected: %s", strerror(errno));

    if (ioctl(fd, BIOCGBLEN, &blen) < 0)
        blen = MON_BUFLEN;

    s_buf = malloc(blen);
    if (!s_buf) {
        close(fd);
        return false;
    }
    s_buflen = blen;

    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    memset(s_slots, 0, sizeof(s_slots));
    s_fd = fd;
    LOGD("TTL monitor listening on %s (%s, %u byte buffer)",
         ni->egress.name, path, blen);
    return true;
}

void dp_monitor_stop(void)
{
    if (s_fd >= 0) { close(s_fd); s_fd = -1; }
    free(s_buf);
    s_buf = NULL;
    s_buflen = 0;
}

static void record(uint32_t addr, uint8_t ttl)
{
    uint32_t h = addr;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;

    ttl_slot_t *slot = &s_slots[h % MON_SLOTS];
    slot->addr = addr;
    slot->ttl = ttl;
    slot->used = true;
}

void dp_monitor_drain(void)
{
    if (s_fd < 0 || !s_buf)
        return;

    for (;;) {
        ssize_t n = read(s_fd, s_buf, s_buflen);
        if (n <= 0)
            return;

        uint8_t *p = s_buf;
        uint8_t *end = s_buf + n;

        while (p + sizeof(struct bpf_hdr) <= end) {
            struct bpf_hdr *bh = (struct bpf_hdr *)p;
            uint8_t *frame = p + bh->bh_hdrlen;

            if (frame + 14 + (int)sizeof(struct ip) <= end &&
                bh->bh_caplen >= 14 + sizeof(struct ip)) {
                struct ip *ip = (struct ip *)(frame + 14);
                if (ip->ip_v == 4)
                    record(ip->ip_src.s_addr, ip->ip_ttl);
            }

            uint8_t *next = p + BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
            if (next <= p)
                break;
            p = next;
        }
    }
}

/*
 * Senders start at 64, 128 or 255. Rounding the observed TTL up to the nearest
 * of those gives the hop count, which is what --auto-ttl budgets against.
 */
int dp_monitor_hops(const void *addr, int af)
{
    if (af != AF_INET || s_fd < 0)
        return -1;

    uint32_t a;
    memcpy(&a, addr, 4);

    uint32_t h = a;
    h ^= h >> 16;
    h *= 0x45d9f3b;
    h ^= h >> 16;

    ttl_slot_t *slot = &s_slots[h % MON_SLOTS];
    if (!slot->used || slot->addr != a)
        return -1;

    int ttl = slot->ttl;
    int start = (ttl <= 64) ? 64 : (ttl <= 128 ? 128 : 255);
    int hops = start - ttl;

    if (hops < 1 || hops > 64)
        return -1;
    return hops;
}
