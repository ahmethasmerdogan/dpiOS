#include "dpios.h"

#include <stdlib.h>
#include <string.h>

#define TLS_REC_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO 0x01
#define TLS_EXT_SERVER_NAME 0x0000
#define TLS_EXT_PADDING 0x0015

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/*
 * Parse a TLS ClientHello sitting at the head of a TCP payload and locate the
 * SNI. Returns false for anything that is not a recognisable ClientHello.
 * A ClientHello split across segments by the sender is not reassembled - we
 * only ever look at what is in front of us.
 */
bool dp_tls_parse(const uint8_t *payload, size_t len, dp_tls_info_t *out)
{
    memset(out, 0, sizeof(*out));

    if (len < 6 || payload[0] != TLS_REC_HANDSHAKE)
        return false;
    if (payload[1] != 0x03)          /* major version of the record layer */
        return false;

    size_t rec_len = rd16(payload + 3);
    out->record_len = rec_len + 5;

    if (payload[5] != TLS_HS_CLIENT_HELLO)
        return false;

    out->is_client_hello = true;

    /* From here on a truncated hello simply means "no SNI found". */
    if (len < 9)
        return true;

    size_t hs_len = rd24(payload + 6);
    size_t limit = 9 + hs_len;
    if (limit > len)
        limit = len;              /* tolerate truncation, scan what we have */

    size_t p = 9;
    if (p + 2 + 32 > limit) return true;
    p += 2;                       /* client_version */
    p += 32;                      /* random */

    if (p + 1 > limit) return true;
    size_t sid_len = payload[p++];
    p += sid_len;

    if (p + 2 > limit) return true;
    size_t cs_len = rd16(payload + p);
    p += 2 + cs_len;

    if (p + 1 > limit) return true;
    size_t comp_len = payload[p++];
    p += comp_len;

    if (p + 2 > limit) return true;
    size_t ext_total = rd16(payload + p);
    p += 2;

    size_t ext_end = p + ext_total;
    if (ext_end > limit)
        ext_end = limit;

    while (p + 4 <= ext_end) {
        uint16_t etype = rd16(payload + p);
        uint16_t elen = rd16(payload + p + 2);
        size_t ebody = p + 4;
        if (ebody + elen > ext_end)
            break;

        if (etype == TLS_EXT_SERVER_NAME && elen >= 5) {
            /* server_name_list: 2b len, then entries of {1b type, 2b len, name} */
            size_t q = ebody + 2;
            size_t list_end = ebody + elen;
            while (q + 3 <= list_end) {
                uint8_t ntype = payload[q];
                uint16_t nlen = rd16(payload + q + 1);
                size_t noff = q + 3;
                if (noff + nlen > list_end)
                    break;
                if (ntype == 0 && nlen > 0) {
                    out->sni_offset = noff;
                    out->sni_len = nlen;
                    size_t copy = nlen < sizeof(out->sni) - 1 ? nlen : sizeof(out->sni) - 1;
                    memcpy(out->sni, payload + noff, copy);
                    out->sni[copy] = '\0';
                    return true;
                }
                q = noff + nlen;
            }
        }
        p = ebody + elen;
    }

    return true;
}

/* ------------------------------------------------- TLS record splitting -- */

/*
 * Some DPI engines reassemble TCP before they inspect, which makes splitting
 * the ClientHello across TCP segments useless - they see the whole thing
 * anyway. Splitting it across two *TLS records* is a different matter: a
 * handshake message is allowed to span records, and an inspector that only
 * parses the first record never sees a complete ClientHello.
 *
 * The catch is that a second record costs 5 more bytes of header, and this
 * design cannot change the length of a segment - the kernel has already
 * committed to covering exactly N bytes at this sequence number. So the five
 * bytes have to come from inside the ClientHello itself.
 *
 * Two places are safe to take them from:
 *   - the padding extension (RFC 7685), which exists to be ignored
 *   - GREASE extensions (RFC 8701), which are deliberate nonsense the server
 *     must ignore; Chromium-based clients always send a couple
 */

#define TLS_EXT_PADDING_ID 0x0015

static bool is_grease_ext(uint16_t t)
{
    /* 0x0a0a, 0x1a1a, ... 0xfafa */
    return ((t & 0x0f0f) == 0x0a0a) && ((t >> 8) == (t & 0xff));
}

/* Locate the extensions block; offsets are relative to the record start. */
static bool find_extensions(const uint8_t *p, size_t len,
                            size_t *ext_len_off, size_t *ext_total)
{
    if (len < 45 || p[0] != TLS_REC_HANDSHAKE || p[5] != TLS_HS_CLIENT_HELLO)
        return false;

    size_t i = 9 + 2 + 32;              /* record+hs header, version, random */
    if (i + 1 > len) return false;
    i += 1 + p[i];                      /* session id */
    if (i + 2 > len) return false;
    i += 2 + rd16(p + i);               /* cipher suites */
    if (i + 1 > len) return false;
    i += 1 + p[i];                      /* compression methods */
    if (i + 2 > len) return false;

    *ext_len_off = i;
    *ext_total = rd16(p + i);
    return (i + 2 + *ext_total) <= len;
}

static void patch_lengths(uint8_t *p, size_t ext_len_off, size_t shrink)
{
    /* extensions block */
    size_t e = rd16(p + ext_len_off) - shrink;
    p[ext_len_off] = (uint8_t)(e >> 8);
    p[ext_len_off + 1] = (uint8_t)(e & 0xff);

    /* handshake message */
    size_t h = rd24(p + 6) - shrink;
    p[6] = (uint8_t)((h >> 16) & 0xff);
    p[7] = (uint8_t)((h >> 8) & 0xff);
    p[8] = (uint8_t)(h & 0xff);

    /* record */
    size_t r = rd16(p + 3) - shrink;
    p[3] = (uint8_t)(r >> 8);
    p[4] = (uint8_t)(r & 0xff);
}

/* Free exactly `need` bytes. Returns the new payload length, or 0 on failure. */
static size_t reclaim_bytes(uint8_t *p, size_t len, size_t need)
{
    size_t ext_len_off, ext_total;
    if (!find_extensions(p, len, &ext_len_off, &ext_total))
        return 0;

    size_t start = ext_len_off + 2;
    size_t end = start + ext_total;

    /* First choice: shrink the padding extension in place. */
    for (size_t i = start; i + 4 <= end; ) {
        uint16_t type = rd16(p + i);
        uint16_t elen = rd16(p + i + 2);
        if (i + 4 + elen > end)
            break;

        if (type == TLS_EXT_PADDING_ID && elen >= need) {
            size_t body = i + 4;
            uint16_t nlen = (uint16_t)(elen - need);
            p[i + 2] = (uint8_t)(nlen >> 8);
            p[i + 3] = (uint8_t)(nlen & 0xff);
            memmove(p + body + nlen, p + body + elen, len - (body + elen));
            patch_lengths(p, ext_len_off, need);
            return len - need;
        }
        i += 4 + elen;
    }

    /* Second choice: drop a GREASE extension whose total size is exactly
     * what we need, so no other extension has to be touched. */
    for (size_t i = start; i + 4 <= end; ) {
        uint16_t type = rd16(p + i);
        uint16_t elen = rd16(p + i + 2);
        if (i + 4 + elen > end)
            break;

        if (is_grease_ext(type) && (size_t)(4 + elen) == need) {
            memmove(p + i, p + i + 4 + elen, len - (i + 4 + elen));
            patch_lengths(p, ext_len_off, need);
            return len - need;
        }
        i += 4 + elen;
    }

    return 0;
}

/*
 * Re-frame a ClientHello that occupies one TLS record into two records,
 * without changing the total number of bytes. Returns the new length, which
 * on success equals `len`, or 0 if the hello had no room to give.
 */
size_t dp_tls_split_records(uint8_t *buf, size_t len, size_t cap)
{
    if (len < 45 || buf[0] != TLS_REC_HANDSHAKE)
        return 0;
    if ((size_t)rd16(buf + 3) + 5 != len)
        return 0;              /* not exactly one record, leave it alone */

    size_t shrunk = reclaim_bytes(buf, len, 5);
    if (shrunk == 0)
        return 0;

    /* Cut inside the hostname where we can - that is the field being matched. */
    dp_tls_info_t info;
    size_t hs_len = shrunk - 5;
    size_t cut;
    if (dp_tls_parse(buf, shrunk, &info) && info.sni_len > 1)
        cut = (info.sni_offset - 5) + info.sni_len / 2;
    else
        cut = 1;

    if (cut < 1) cut = 1;
    if (cut >= hs_len) cut = hs_len - 1;

    uint8_t tmp[DPIOS_MAX_PACKET / 8];
    if (len > sizeof(tmp) || len > cap)
        return 0;

    const uint8_t *hs = buf + 5;
    size_t o = 0;

    tmp[o++] = TLS_REC_HANDSHAKE; tmp[o++] = buf[1]; tmp[o++] = buf[2];
    tmp[o++] = (uint8_t)(cut >> 8); tmp[o++] = (uint8_t)(cut & 0xff);
    memcpy(tmp + o, hs, cut); o += cut;

    size_t rest = hs_len - cut;
    tmp[o++] = TLS_REC_HANDSHAKE; tmp[o++] = buf[1]; tmp[o++] = buf[2];
    tmp[o++] = (uint8_t)(rest >> 8); tmp[o++] = (uint8_t)(rest & 0xff);
    memcpy(tmp + o, hs + cut, rest); o += rest;

    if (o != len)
        return 0;              /* refuse to change the length, ever */

    memcpy(buf, tmp, o);
    return o;
}

/*
 * Build a syntactically valid ClientHello for a benign hostname. This is what
 * gets sent as the decoy packet - the DPI box latches onto it, the real server
 * throws it away because of the broken TTL / checksum / sequence number.
 *
 * When target_len is non-zero the hello is padded to exactly that many bytes
 * so the decoy is indistinguishable in size from the request it shadows.
 */
size_t dp_tls_build_fake_hello(uint8_t *buf, size_t buflen, const char *sni,
                               size_t target_len)
{
    size_t sni_len = strlen(sni);
    if (sni_len > 200)
        sni_len = 200;

    /* Fixed part: record(5) + hs hdr(4) + ver(2) + random(32) + sid(1)
     *             + ciphers(2+2) + comp(1+1) + ext_len(2)
     * SNI ext: 4 + 2 + 1 + 2 + sni_len
     */
    size_t sni_ext = 4 + 2 + 1 + 2 + sni_len;
    size_t base = 5 + 4 + 2 + 32 + 1 + 4 + 2 + 2 + sni_ext;

    size_t pad_ext = 0;
    if (target_len > base + 4)
        pad_ext = target_len - base;      /* 4 byte ext header + payload */
    else if (target_len != 0 && target_len < base)
        target_len = 0;                   /* cannot shrink below the minimum */

    size_t total = base + pad_ext;
    if (total > buflen)
        return 0;

    uint8_t *p = buf;

    /* TLS record header - length patched at the end */
    *p++ = TLS_REC_HANDSHAKE;
    *p++ = 0x03; *p++ = 0x01;
    uint8_t *rec_len_at = p; p += 2;

    /* Handshake header */
    *p++ = TLS_HS_CLIENT_HELLO;
    uint8_t *hs_len_at = p; p += 3;

    *p++ = 0x03; *p++ = 0x03;             /* client_version = TLS 1.2 */
    arc4random_buf(p, 32); p += 32;       /* random */
    *p++ = 0x00;                          /* session_id length */

    *p++ = 0x00; *p++ = 0x02;             /* cipher_suites length */
    *p++ = 0x13; *p++ = 0x01;             /* TLS_AES_128_GCM_SHA256 */

    *p++ = 0x01; *p++ = 0x00;             /* compression: null */

    uint8_t *ext_len_at = p; p += 2;
    uint8_t *ext_start = p;

    /* server_name */
    *p++ = 0x00; *p++ = 0x00;
    *p++ = (uint8_t)(((sni_len + 5) >> 8) & 0xff);
    *p++ = (uint8_t)((sni_len + 5) & 0xff);
    *p++ = (uint8_t)(((sni_len + 3) >> 8) & 0xff);
    *p++ = (uint8_t)((sni_len + 3) & 0xff);
    *p++ = 0x00;                          /* host_name */
    *p++ = (uint8_t)((sni_len >> 8) & 0xff);
    *p++ = (uint8_t)(sni_len & 0xff);
    memcpy(p, sni, sni_len); p += sni_len;

    /* padding extension to reach the requested size */
    if (pad_ext >= 4) {
        size_t plen = pad_ext - 4;
        *p++ = (uint8_t)((TLS_EXT_PADDING >> 8) & 0xff);
        *p++ = (uint8_t)(TLS_EXT_PADDING & 0xff);
        *p++ = (uint8_t)((plen >> 8) & 0xff);
        *p++ = (uint8_t)(plen & 0xff);
        memset(p, 0, plen); p += plen;
    }

    size_t ext_bytes = (size_t)(p - ext_start);
    ext_len_at[0] = (uint8_t)((ext_bytes >> 8) & 0xff);
    ext_len_at[1] = (uint8_t)(ext_bytes & 0xff);

    size_t hs_bytes = (size_t)(p - (hs_len_at + 3));
    hs_len_at[0] = (uint8_t)((hs_bytes >> 16) & 0xff);
    hs_len_at[1] = (uint8_t)((hs_bytes >> 8) & 0xff);
    hs_len_at[2] = (uint8_t)(hs_bytes & 0xff);

    size_t rec_bytes = (size_t)(p - (rec_len_at + 2));
    rec_len_at[0] = (uint8_t)((rec_bytes >> 8) & 0xff);
    rec_len_at[1] = (uint8_t)(rec_bytes & 0xff);

    return (size_t)(p - buf);
}
