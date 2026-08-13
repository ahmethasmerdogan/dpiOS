#include "dpios.h"

#include <stdio.h>
#include <string.h>

dp_config_t g_cfg;

void dp_config_defaults(dp_config_t *c)
{
    memset(c, 0, sizeof(*c));

    c->ports[0] = 80;
    c->ports[1] = 443;
    c->nports = 2;

    c->max_payload = 1500;
    c->fake_resend = 1;
    c->wrong_seq_delta = 0x10000;
    c->auto_ttl_delta = 1;
    c->auto_ttl_min = 3;
    c->auto_ttl_max = 10;
    c->inject_mode = INJECT_BPF;
    c->action = DP_ACTION_RUN;
    c->foreground = true;

    strlcpy(c->fake_sni, "www.w3.org", sizeof(c->fake_sni));
}

bool dp_config_add_port(dp_config_t *c, int port)
{
    if (port < 1 || port > 65535)
        return false;
    for (int i = 0; i < c->nports; i++)
        if (c->ports[i] == (uint16_t)port)
            return true;
    if (c->nports >= DPIOS_MAX_PORTS)
        return false;
    c->ports[c->nports++] = (uint16_t)port;
    return true;
}

bool dp_config_has_port(const dp_config_t *c, uint16_t port)
{
    for (int i = 0; i < c->nports; i++)
        if (c->ports[i] == port)
            return true;
    return false;
}

/*
 * Presets follow GoodbyeDPI's numbering so muscle memory carries over. They
 * are not byte-identical - a few of the Windows-only tricks have no macOS
 * equivalent - but the intent of each level is preserved: 1-4 are the gentle
 * HTTP-oriented modes, 5-9 escalate into decoy packets.
 */
bool dp_config_apply_preset(dp_config_t *c, int preset)
{
    c->preset = preset;

    switch (preset) {
    case 1:
        c->host_replace = true; c->host_nospace = true; c->method_space = true;
        c->frag_http = 2; c->frag_persistent = 2; c->frag_https = 2;
        break;
    case 2:
        c->host_replace = true; c->host_nospace = true; c->method_space = true;
        c->frag_http = 2; c->frag_persistent = 2; c->frag_https = 40;
        break;
    case 3:
        c->host_replace = true; c->host_nospace = true; c->method_space = true;
        c->frag_https = 40;
        break;
    case 4:
        c->host_replace = true; c->host_nospace = true; c->method_space = true;
        break;
    case 5:
        c->frag_http = 2; c->frag_https = 2;
        c->reverse_frag = true;
        c->fake_enable = true; c->auto_ttl = true;
        break;
    case 6:
        c->frag_http = 2; c->frag_https = 2;
        c->reverse_frag = true;
        c->fake_enable = true; c->wrong_seq = true;
        break;
    case 7:
        c->frag_http = 2; c->frag_https = 2;
        c->reverse_frag = true;
        c->fake_enable = true; c->wrong_chksum = true;
        break;
    case 8:
        c->frag_http = 2; c->frag_https = 2;
        c->reverse_frag = true;
        c->fake_enable = true; c->wrong_seq = true; c->wrong_chksum = true;
        break;
    case 9:
        c->frag_http = 2; c->frag_https = 2;
        c->reverse_frag = true; c->frag_sni = true;
        c->fake_enable = true; c->wrong_seq = true; c->wrong_chksum = true;
        break;
    default:
        return false;
    }

    return true;
}

void dp_config_dump(const dp_config_t *c)
{
    char ports[256] = {0};
    size_t n = 0;
    for (int i = 0; i < c->nports; i++)
        n += (size_t)snprintf(ports + n, sizeof(ports) - n, "%s%u",
                              i ? "," : "", (unsigned)c->ports[i]);

    LOGI("configuration:");
    if (c->preset)
        LOGI("  preset            -%d", c->preset);
    LOGI("  ports             %s", ports);
    LOGI("  http fragment     %d%s", c->frag_http,
         c->frag_persistent ? " (persistent requests too)" : "");
    LOGI("  https fragment    %d%s", c->frag_https,
         c->frag_sni ? " (split inside the hostname)" : "");
    LOGI("  fragment order    %s", c->reverse_frag ? "reversed" : "normal");
    LOGI("  fragment layer    %s", c->ip_frag ? "IP" : "TCP");
    LOGI("  header tricks     %s%s%s%s",
         c->host_replace ? "hoSt " : "",
         c->host_case ? "mixed-case " : "",
         c->host_nospace ? "no-space " : "",
         c->method_space ? "method-space" : "");
    if (c->fake_enable) {
        LOGI("  decoy packets     on (sni %s, resend %d)",
             c->fake_sni, c->fake_resend);
        if (c->auto_ttl)
            LOGI("  decoy ttl         auto (delta %d, range %d-%d)",
                 c->auto_ttl_delta, c->auto_ttl_min, c->auto_ttl_max);
        else if (c->fake_ttl)
            LOGI("  decoy ttl         %d", c->fake_ttl);
        if (c->wrong_seq)
            LOGI("  decoy sequence    real - %u", c->wrong_seq_delta);
        if (c->wrong_chksum)
            LOGI("  decoy checksum    deliberately broken");
    } else {
        LOGI("  decoy packets     off");
    }
    LOGI("  injection         %s", c->inject_mode == INJECT_BPF ? "bpf" : "raw");
    LOGI("  ipv6              %s", c->enable_ipv6 ? "on" : "off");
    if (c->blacklist_path[0])
        LOGI("  blacklist         %s", c->blacklist_path);
    if (c->whitelist_path[0])
        LOGI("  whitelist         %s", c->whitelist_path);
}
