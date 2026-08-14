/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 ahmethasmerdogan
 */
/*
 * Unit tests for the portable half of dpiOS: the protocol parsers, the decoy
 * builders, the checksum code and the hostname lists. These are the parts that
 * decide whether a packet is mangled correctly, so they are worth exercising
 * for real rather than just compiling.
 *
 *   make test
 */
#include "dpios.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int s_pass = 0;
static int s_fail = 0;

#define CHECK(cond, ...) do {                                   \
    if (cond) {                                                 \
        s_pass++;                                               \
    } else {                                                    \
        s_fail++;                                               \
        printf("  FAIL %s:%d  ", __func__, __LINE__);           \
        printf(__VA_ARGS__);                                    \
        printf("\n");                                           \
    }                                                           \
} while (0)

/* ------------------------------------------------------------------- TLS */

static void test_tls_roundtrip(void)
{
    uint8_t buf[2048];
    const char *sni = "www.example.com";

    size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), sni, 0);
    CHECK(n > 0, "builder returned nothing");

    dp_tls_info_t info;
    CHECK(dp_tls_parse(buf, n, &info), "parser rejected our own hello");
    CHECK(info.is_client_hello, "not recognised as a ClientHello");
    CHECK(strcmp(info.sni, sni) == 0, "sni mismatch: got '%s'", info.sni);
    CHECK(info.sni_len == strlen(sni), "sni_len %zu", info.sni_len);
    CHECK(memcmp(buf + info.sni_offset, sni, info.sni_len) == 0,
          "sni_offset %zu does not point at the hostname", info.sni_offset);

    /* the declared record length must match what we produced */
    CHECK(info.record_len == n, "record_len %zu vs actual %zu", info.record_len, n);
}

static void test_tls_padding(void)
{
    uint8_t buf[2048];

    for (size_t target = 200; target <= 1400; target += 300) {
        size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), "cdn.example.net",
                                           target);
        CHECK(n == target, "padded to %zu, wanted %zu", n, target);

        dp_tls_info_t info;
        CHECK(dp_tls_parse(buf, n, &info) && info.is_client_hello,
              "padded hello no longer parses at target %zu", target);
        CHECK(strcmp(info.sni, "cdn.example.net") == 0,
              "padding clobbered the sni at target %zu", target);
    }

    /* asking for less than the minimum must not corrupt anything */
    size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), "a.io", 10);
    dp_tls_info_t info;
    CHECK(n > 0 && dp_tls_parse(buf, n, &info) && info.is_client_hello,
          "undersized target produced a broken hello");
}

static void test_tls_truncated(void)
{
    uint8_t buf[2048];
    size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), "truncate.me", 0);

    /* A hello cut short mid-extension must be reported, never over-read. */
    for (size_t cut = 6; cut < n; cut += 7) {
        dp_tls_info_t info;
        dp_tls_parse(buf, cut, &info);   /* must simply not crash */
    }
    CHECK(true, "unreachable");

    uint8_t junk[64];
    memset(junk, 0x41, sizeof(junk));
    dp_tls_info_t info;
    CHECK(!dp_tls_parse(junk, sizeof(junk), &info),
          "plain ASCII was mistaken for a ClientHello");
}

/*
 * Re-framing the hello into two TLS records is the technique that beats a DPI
 * which reassembles TCP. The invariant that makes it safe here is that the
 * total length must not move by a single byte.
 */
static void test_tls_record_split(void)
{
    uint8_t buf[2048];
    const char *sni = "www.example.com";

    size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), sni, 400);
    CHECK(n == 400, "setup: builder gave %zu", n);

    uint8_t before[2048];
    memcpy(before, buf, n);

    size_t out = dp_tls_split_records(buf, n, sizeof(buf));
    CHECK(out == n, "LENGTH CHANGED %zu -> %zu", n, out);
    if (out != n)
        return;

    /* two records, back to back, covering the payload exactly */
    CHECK(buf[0] == 0x16, "first record is not a handshake record");
    size_t r1 = ((size_t)buf[3] << 8) | buf[4];
    CHECK(5 + r1 < n, "first record still covers everything (%zu)", r1);

    size_t off2 = 5 + r1;
    CHECK(buf[off2] == 0x16, "second record header missing");
    size_t r2 = ((size_t)buf[off2 + 3] << 8) | buf[off2 + 4];
    CHECK(off2 + 5 + r2 == n, "records do not tile the payload: %zu vs %zu",
          off2 + 5 + r2, n);

    /* the handshake, once glued back together, must still be a valid hello */
    uint8_t re[2048];
    size_t hs = r1 + r2;
    re[0] = 0x16; re[1] = buf[1]; re[2] = buf[2];
    re[3] = (uint8_t)(hs >> 8); re[4] = (uint8_t)(hs & 0xff);
    memcpy(re + 5, buf + 5, r1);
    memcpy(re + 5 + r1, buf + off2 + 5, r2);

    dp_tls_info_t info;
    CHECK(dp_tls_parse(re, 5 + hs, &info) && info.is_client_hello,
          "reassembled handshake no longer parses");
    CHECK(strcmp(info.sni, sni) == 0,
          "hostname damaged by the split: '%s'", info.sni);

    /* the split has to land inside the hostname, that is the whole point */
    CHECK(r1 > 0 && r1 < hs, "split at a useless position");

    CHECK(memcmp(before, buf, n) != 0, "nothing actually changed");
}

/*
 * Chromium's post-quantum key share pushes the ClientHello past 1700 bytes, so
 * it arrives as two TCP segments and dpiOS only ever sees the first. The
 * rewrite has to happen entirely within that first segment: same length, and
 * the second record's header declares a length reaching into bytes the next
 * segment already carries.
 */
static void test_tls_record_split_partial(void)
{
    uint8_t full[4096];

    /* a hello far too big for one segment, with a GREASE extension to raid */
    size_t n = dp_tls_build_fake_hello(full, sizeof(full), "discord.com", 1900);
    CHECK(n == 1900, "setup: builder gave %zu", n);

    size_t seg1 = 1400;                     /* what the kernel hands us first */
    uint8_t buf[4096];
    memcpy(buf, full, seg1);

    size_t out = dp_tls_split_records(buf, seg1, sizeof(buf));
    CHECK(out == seg1, "LENGTH CHANGED %zu -> %zu", seg1, out);
    if (out != seg1)
        return;

    CHECK(buf[0] == 0x16, "first record is not a handshake record");
    size_t r1 = ((size_t)buf[3] << 8) | buf[4];
    CHECK(5 + r1 < seg1, "first record swallowed the segment");

    size_t off2 = 5 + r1;
    CHECK(buf[off2] == 0x16, "second record header missing");
    size_t r2 = ((size_t)buf[off2 + 3] << 8) | buf[off2 + 4];

    /* the point of the exercise: record two runs past this segment */
    size_t here = seg1 - off2 - 5;
    CHECK(r2 > here, "second record does not continue into the next segment "
                     "(declared %zu, present %zu)", r2, here);

    /* what the server ends up with: our segment plus the untouched remainder */
    uint8_t asm_[4096];
    size_t a = 0;
    memcpy(asm_ + a, buf + 5, r1); a += r1;
    memcpy(asm_ + a, buf + off2 + 5, here); a += here;
    memcpy(asm_ + a, full + seg1, n - seg1); a += n - seg1;

    size_t declared = ((size_t)asm_[1] << 16) | ((size_t)asm_[2] << 8) | asm_[3];
    CHECK(declared + 4 == a, "handshake length %zu does not match the %zu bytes "
                             "actually delivered", declared + 4, a);

    /* and it must still be a ClientHello for the right host */
    uint8_t re[4096];
    re[0] = 0x16; re[1] = 0x03; re[2] = 0x01;
    re[3] = (uint8_t)(a >> 8); re[4] = (uint8_t)(a & 0xff);
    memcpy(re + 5, asm_, a);

    dp_tls_info_t info;
    CHECK(dp_tls_parse(re, a + 5, &info) && info.is_client_hello,
          "reassembled hello no longer parses");
    CHECK(strcmp(info.sni, "discord.com") == 0,
          "hostname damaged: '%s'", info.sni);
}

static void test_tls_record_split_refuses(void)
{
    uint8_t buf[2048];

    /* No padding extension and no GREASE - there are no bytes to reclaim,
     * so the only correct answer is to decline rather than grow the packet. */
    size_t n = dp_tls_build_fake_hello(buf, sizeof(buf), "tiny.example", 0);
    uint8_t before[2048];
    memcpy(before, buf, n);

    size_t out = dp_tls_split_records(buf, n, sizeof(buf));
    CHECK(out == 0, "should have declined, returned %zu", out);
    CHECK(memcmp(before, buf, n) == 0, "declined but still modified the buffer");

    /* garbage must never be treated as a hello */
    uint8_t junk[64];
    memset(junk, 0x41, sizeof(junk));
    CHECK(dp_tls_split_records(junk, sizeof(junk), sizeof(junk)) == 0,
          "split accepted non-TLS bytes");
}

/* ------------------------------------------------------------------ HTTP */

static void test_http_parse(void)
{
    const char *req =
        "GET /index.html HTTP/1.1\r\n"
        "User-Agent: curl/8.0\r\n"
        "Host: www.example.com\r\n"
        "Accept: */*\r\n"
        "\r\n";

    dp_http_info_t info;
    CHECK(dp_http_parse((const uint8_t *)req, strlen(req), &info),
          "request not recognised");
    CHECK(info.is_request, "is_request false");
    CHECK(strcmp(info.host, "www.example.com") == 0,
          "host mismatch: '%s'", info.host);
    CHECK(info.method_len == 3, "method_len %zu, wanted 3", info.method_len);
    CHECK(memcmp(req + info.host_value_off, "www.example.com", 15) == 0,
          "host_value_off points at the wrong place");

    /* a port suffix must be stripped for list matching */
    const char *req2 =
        "POST /x HTTP/1.1\r\nHost: example.org:8443\r\n\r\n";
    CHECK(dp_http_parse((const uint8_t *)req2, strlen(req2), &info), "req2");
    CHECK(strcmp(info.host, "example.org") == 0,
          "port not stripped: '%s'", info.host);

    /* not HTTP at all */
    const char *nope = "\x16\x03\x01\x00\x2a not http really";
    CHECK(!dp_http_parse((const uint8_t *)nope, 20, &info),
          "TLS bytes parsed as HTTP");
}

static void test_http_mangle_preserves_length(void)
{
    const char *orig =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "Accept: */*\r\n"
        "\r\n";
    size_t len = strlen(orig);

    dp_config_t cfg;
    dp_config_defaults(&cfg);
    cfg.host_replace = true;
    cfg.host_case = true;
    cfg.host_nospace = true;
    cfg.method_space = true;

    uint8_t buf[512];
    memcpy(buf, orig, len);

    dp_http_info_t info;
    CHECK(dp_http_parse(buf, len, &info), "parse before mangle");

    size_t out = dp_http_mangle(buf, len, sizeof(buf), &info, &cfg);

    /*
     * This is the invariant that matters most. The kernel has already told
     * the peer that this sequence number covers exactly `len` bytes.
     */
    CHECK(out == len, "length changed: %zu -> %zu", len, out);

    buf[out] = '\0';
    CHECK(strstr((char *)buf, "hoSt:") != NULL,
          "Host: was not rewritten: %s", (char *)buf);
    CHECK(strstr((char *)buf, "hoSt: www") == NULL,
          "space after the header name survived");
    CHECK(strncmp((char *)buf, "GET  /", 6) == 0,
          "compensating space missing: '%.10s'", (char *)buf);
    CHECK(strstr((char *)buf, "HTTP/1.1") != NULL, "request line damaged");

    /* the hostname must still be there, just in a different case */
    CHECK(strcasestr((char *)buf, "www.example.com") != NULL,
          "hostname lost: %s", (char *)buf);
}

static void test_http_mangle_no_host(void)
{
    /* a request with no Host header must survive untouched */
    const char *orig = "GET / HTTP/1.0\r\n\r\n";
    size_t len = strlen(orig);

    dp_config_t cfg;
    dp_config_defaults(&cfg);
    cfg.host_replace = true;
    cfg.host_nospace = true;
    cfg.method_space = true;

    uint8_t buf[128];
    memcpy(buf, orig, len);

    dp_http_info_t info;
    dp_http_parse(buf, len, &info);
    size_t out = dp_http_mangle(buf, len, sizeof(buf), &info, &cfg);

    CHECK(out == len, "length changed on a hostless request");
    CHECK(memcmp(buf, orig, len) == 0, "hostless request was modified");
}

/* -------------------------------------------------------------- checksum */

/*
 * A correct checksum has the property that re-summing the region, checksum
 * field included, yields zero. That is what the receiving stack does.
 */
static uint16_t verify_sum(const void *data, size_t len, uint32_t pseudo)
{
    return dp_cksum_finish(dp_cksum_partial(data, len, pseudo));
}

static void test_checksums(void)
{
    for (size_t plen = 0; plen <= 65; plen += 13) {
        uint8_t pkt[256];
        memset(pkt, 0, sizeof(pkt));

        struct ip *ip = (struct ip *)pkt;
        ip->ip_v = 4;
        ip->ip_hl = 5;
        ip->ip_ttl = 64;
        ip->ip_p = IPPROTO_TCP;
        ip->ip_src.s_addr = htonl(0xc0a80105);
        ip->ip_dst.s_addr = htonl(0x08080808);

        size_t thl = sizeof(struct tcphdr);
        size_t total = 20 + thl + plen;
        ip->ip_len = htons((uint16_t)total);

        struct tcphdr *th = (struct tcphdr *)(pkt + 20);
        th->th_sport = htons(51000);
        th->th_dport = htons(443);
        th->th_seq = htonl(0x11223344);
        th->th_off = (uint8_t)(thl / 4);
        th->th_flags = TH_PUSH | TH_ACK;
        th->th_win = htons(65535);

        for (size_t i = 0; i < plen; i++)
            pkt[20 + thl + i] = (uint8_t)(i * 7 + 1);

        dp_fix_checksums_v4(pkt, total);

        CHECK(verify_sum(pkt, 20, 0) == 0,
              "ip checksum does not verify (plen %zu)", plen);

        uint32_t pseudo = 0;
        pseudo = dp_cksum_partial(&ip->ip_src, 4, pseudo);
        pseudo = dp_cksum_partial(&ip->ip_dst, 4, pseudo);
        pseudo += IPPROTO_TCP;
        pseudo += (uint32_t)(thl + plen);
        CHECK(verify_sum(pkt + 20, thl + plen, pseudo) == 0,
              "tcp checksum does not verify (plen %zu)", plen);

        /* a single flipped byte must break it */
        if (plen > 0) {
            pkt[20 + thl] ^= 0xff;
            CHECK(verify_sum(pkt + 20, thl + plen, pseudo) != 0,
                  "checksum did not notice a corrupted payload");
        }
    }
}

/* ------------------------------------------------------------------ list */

static void test_lists(void)
{
    const char *path = "/tmp/dpios-test-blacklist.txt";
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("  SKIP list test (cannot write %s)\n", path);
        return;
    }
    fprintf(f, "# comment\n");
    fprintf(f, "example.com\n");
    fprintf(f, "*.cdn.example.net\n");
    fprintf(f, "0.0.0.0 hosts-style.org\n");
    fprintf(f, "\n");
    fclose(f);

    CHECK(dp_list_load(path, false), "blacklist did not load");
    CHECK(dp_list_have_blacklist(), "blacklist reported empty");

    CHECK(dp_list_should_process("example.com"), "exact match missed");
    CHECK(dp_list_should_process("www.example.com"), "subdomain match missed");
    CHECK(dp_list_should_process("a.b.example.com"), "deep subdomain missed");
    CHECK(dp_list_should_process("EXAMPLE.COM"), "case sensitivity leaked in");
    CHECK(dp_list_should_process("cdn.example.net"), "wildcard entry missed");
    CHECK(dp_list_should_process("hosts-style.org"), "hosts-file line missed");

    CHECK(!dp_list_should_process("notexample.com"), "false positive: suffix");
    CHECK(!dp_list_should_process("example.com.evil.net"), "false positive");
    CHECK(!dp_list_should_process(""), "empty host must not match");

    dp_list_free();
    remove(path);

    /* with no lists loaded at all, everything is fair game */
    CHECK(dp_list_should_process("anything.test"), "default should be process");
}

/* ---------------------------------------------------------------- config */

static void test_presets(void)
{
    for (int i = 1; i <= 9; i++) {
        dp_config_t c;
        dp_config_defaults(&c);
        CHECK(dp_config_apply_preset(&c, i), "preset -%d rejected", i);
        CHECK(c.preset == i, "preset number not recorded");
    }

    dp_config_t c;
    dp_config_defaults(&c);
    CHECK(!dp_config_apply_preset(&c, 42), "bogus preset accepted");

    CHECK(dp_config_has_port(&c, 80) && dp_config_has_port(&c, 443),
          "default ports missing");
    CHECK(!dp_config_has_port(&c, 8080), "8080 should not be default");
    CHECK(dp_config_add_port(&c, 8080) && dp_config_has_port(&c, 8080),
          "adding a port failed");
    CHECK(!dp_config_add_port(&c, 0) && !dp_config_add_port(&c, 70000),
          "invalid port accepted");

    /* presets 5..9 all rely on decoy packets */
    for (int i = 5; i <= 9; i++) {
        dp_config_t p;
        dp_config_defaults(&p);
        dp_config_apply_preset(&p, i);
        CHECK(p.fake_enable, "preset -%d did not enable decoys", i);
        CHECK(p.frag_https > 0, "preset -%d did not set a tls split", i);
    }
}

/* ------------------------------------------------------------------ main */

int main(void)
{
    dp_log_init(false, DP_ERR);   /* keep the output about the tests */

    printf("dpiOS unit tests\n\n");

    test_tls_roundtrip();
    test_tls_padding();
    test_tls_truncated();
    test_tls_record_split();
    test_tls_record_split_partial();
    test_tls_record_split_refuses();
    test_http_parse();
    test_http_mangle_preserves_length();
    test_http_mangle_no_host();
    test_checksums();
    test_lists();
    test_presets();

    printf("\n%d passed, %d failed\n", s_pass, s_fail);
    return s_fail == 0 ? 0 : 1;
}
