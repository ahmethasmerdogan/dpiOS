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
