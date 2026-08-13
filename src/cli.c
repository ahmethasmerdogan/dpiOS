#include "dpios.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    OPT_FRAG_SNI = 1000,
    OPT_REVERSE_FRAG,
    OPT_IP_FRAG,
    OPT_FAKE,
    OPT_FAKE_SNI,
    OPT_FAKE_RESEND,
    OPT_SET_TTL,
    OPT_AUTO_TTL,
    OPT_WRONG_CHKSUM,
    OPT_WRONG_SEQ,
    OPT_SEQ_DELTA,
    OPT_PORT,
    OPT_MAX_PAYLOAD,
    OPT_IPV6,
    OPT_IFACE,
    OPT_INJECT,
    OPT_BLACKLIST,
    OPT_WHITELIST,
    OPT_CHECK,
    OPT_UNLOAD,
    OPT_SYSLOG,
    OPT_DRY_RUN,
    OPT_QUIET,
    OPT_NO_UI,
    OPT_RECORD_FRAG,
    OPT_NO_RECORD_FRAG,
    OPT_DOH,
    OPT_NO_DOH,
    OPT_DOH_URL,
    OPT_DOH_BOOTSTRAP,
    OPT_BLOCK_QUIC
};

static const struct option k_long[] = {
    { "frag-http",     required_argument, NULL, 'f' },
    { "frag-https",    required_argument, NULL, 'e' },
    { "frag-persist",  required_argument, NULL, 'k' },
    { "host-replace",  no_argument,       NULL, 'r' },
    { "host-nospace",  no_argument,       NULL, 's' },
    { "host-case",     no_argument,       NULL, 'm' },
    { "method-space",  no_argument,       NULL, 'a' },
    { "frag-sni",      no_argument,       NULL, OPT_FRAG_SNI },
    { "record-frag",   no_argument,       NULL, OPT_RECORD_FRAG },
    { "no-record-frag", no_argument,      NULL, OPT_NO_RECORD_FRAG },
    { "doh",           no_argument,       NULL, OPT_DOH },
    { "no-doh",        no_argument,       NULL, OPT_NO_DOH },
    { "doh-url",       required_argument, NULL, OPT_DOH_URL },
    { "doh-bootstrap", required_argument, NULL, OPT_DOH_BOOTSTRAP },
    { "reverse-frag",  no_argument,       NULL, OPT_REVERSE_FRAG },
    { "ip-frag",       no_argument,       NULL, OPT_IP_FRAG },
    { "fake",          no_argument,       NULL, OPT_FAKE },
    { "fake-sni",      required_argument, NULL, OPT_FAKE_SNI },
    { "fake-resend",   required_argument, NULL, OPT_FAKE_RESEND },
    { "set-ttl",       required_argument, NULL, OPT_SET_TTL },
    { "auto-ttl",      optional_argument, NULL, OPT_AUTO_TTL },
    { "wrong-chksum",  no_argument,       NULL, OPT_WRONG_CHKSUM },
    { "wrong-seq",     no_argument,       NULL, OPT_WRONG_SEQ },
    { "seq-delta",     required_argument, NULL, OPT_SEQ_DELTA },
    { "port",          required_argument, NULL, OPT_PORT },
    { "max-payload",   required_argument, NULL, OPT_MAX_PAYLOAD },
    { "ipv6",          no_argument,       NULL, OPT_IPV6 },
    { "block-quic",    no_argument,       NULL, OPT_BLOCK_QUIC },
    { "iface",         required_argument, NULL, OPT_IFACE },
    { "inject",        required_argument, NULL, OPT_INJECT },
    { "blacklist",     required_argument, NULL, OPT_BLACKLIST },
    { "whitelist",     required_argument, NULL, OPT_WHITELIST },
    { "check",         no_argument,       NULL, OPT_CHECK },
    { "unload",        no_argument,       NULL, OPT_UNLOAD },
    { "syslog",        no_argument,       NULL, OPT_SYSLOG },
    { "no-ui",         no_argument,       NULL, OPT_NO_UI },
    { "dry-run",       no_argument,       NULL, OPT_DRY_RUN },
    { "quiet",         no_argument,       NULL, OPT_QUIET },
    { "verbose",       no_argument,       NULL, 'v' },
    { "version",       no_argument,       NULL, 'V' },
    { "help",          no_argument,       NULL, 'h' },
    { NULL, 0, NULL, 0 }
};

void dp_usage(const char *argv0)
{
    printf(
"dpiOS %s - DPI circumvention for macOS on Apple Silicon\n"
"\n"
"Usage: sudo %s [options]\n"
"\n"
"Presets (same numbering as GoodbyeDPI):\n"
"  -1 .. -4          HTTP oriented: header tricks plus light fragmentation\n"
"  -5 .. -9          add decoy packets; -9 is the most aggressive\n"
"                    start with -5, fall back to -6/-7 if your ISP resists\n"
"\n"
"Fragmentation:\n"
"  -f, --frag-http N     split an HTTP request after N bytes\n"
"  -e, --frag-https N    split a TLS ClientHello after N bytes (default 2)\n"
"  -k, --frag-persist N  also split requests that reuse a connection\n"
"      --frag-sni        split in the middle of the hostname instead\n"
"      --record-frag     also split the ClientHello across two TLS records\n"
"                        (on by default; beats DPI that reassembles TCP)\n"
"      --no-record-frag  turn that off\n"
"      --reverse-frag    put the second fragment on the wire first\n"
"      --ip-frag         fragment at the IP layer rather than the TCP layer\n"
"\n"
"HTTP header tricks:\n"
"  -r, --host-replace    send \"hoSt:\" instead of \"Host:\"\n"
"  -m, --host-case       randomise the case of the hostname\n"
"  -s, --host-nospace    drop the space after the header name\n"
"  -a, --method-space    extra space between the method and the URI\n"
"                        (-s and -a always travel together: the request has\n"
"                         to keep its exact length or the stream desyncs)\n"
"\n"
"Decoy packets:\n"
"      --fake            send a decoy request ahead of the real one\n"
"      --fake-sni HOST   hostname to put in the decoy (default www.w3.org)\n"
"      --fake-resend N   send the decoy N times\n"
"      --set-ttl N       give the decoy a TTL that expires before the server\n"
"      --auto-ttl[=d-min-max]  derive that TTL from the observed hop count\n"
"      --wrong-chksum    give the decoy a broken TCP checksum\n"
"      --wrong-seq       give the decoy an out-of-window sequence number\n"
"      --seq-delta N     how far out of window (default 65536)\n"
"\n"
"DNS (ISS DNS sorgularini engelliyorsa):\n"
"      --doh             run a local DNS-over-HTTPS resolver on 127.0.0.1:53\n"
"                        and point the system at it while dpiOS runs\n"
"      --doh-url URL     which resolver (default cloudflare-dns.com)\n"
"      --doh-bootstrap IP  its address, so startup needs no DNS\n"
"\n"
"Scope:\n"
"      --port N          additional destination port (repeatable)\n"
"      --max-payload N   ignore packets with a payload above N bytes\n"
"      --blacklist FILE  only process hostnames listed in FILE\n"
"      --whitelist FILE  never process hostnames listed in FILE\n"
"      --iface NAME      force the egress interface\n"
"      --inject bpf|raw  how to put packets back on the wire (default bpf)\n"
"      --ipv6            divert IPv6 as well (experimental)\n"
"      --block-quic      drop UDP/443 so browsers fall back to TCP,\n"
"                        where dpiOS can actually reach the handshake\n"
"\n"
"Diagnostics and control:\n"
"      --check           run through every subsystem and report what works\n"
"      --unload          flush leftover pf rules and exit\n"
"      --dry-run         detect and log, but forward everything untouched\n"
"      --no-ui           plain log lines instead of the live panel\n"
"  -v, --verbose         repeatable; -vv adds per-packet tracing\n"
"                        (either of these turns the live panel off)\n"
"      --quiet           errors only\n"
"      --syslog          also log to syslog (used by the launchd job)\n"
"  -V, --version         print the version\n"
"  -h, --help            this text\n"
"\n"
"If the daemon ever dies without cleaning up, restore networking with:\n"
"  sudo pfctl -a %s -F all\n",
    DPIOS_VERSION, argv0, DPIOS_ANCHOR);
}

static bool parse_auto_ttl(const char *arg, dp_config_t *c)
{
    c->auto_ttl = true;
    if (!arg || !*arg)
        return true;

    int d = 0, lo = 0, hi = 0;
    if (sscanf(arg, "%d-%d-%d", &d, &lo, &hi) == 3) {
        c->auto_ttl_delta = d;
        c->auto_ttl_min = lo;
        c->auto_ttl_max = hi;
        return true;
    }
    if (sscanf(arg, "%d", &d) == 1) {
        c->auto_ttl_delta = d;
        return true;
    }
    LOGE("--auto-ttl expects a number or delta-min-max, got '%s'", arg);
    return false;
}

int dp_cli_parse(int argc, char **argv, dp_config_t *c)
{
    int verbosity = 0;
    int opt;
    bool ports_reset = false;

    while ((opt = getopt_long(argc, argv, "123456789f:e:k:rsmapvVh",
                              k_long, NULL)) != -1) {
        switch (opt) {
        case '1': case '2': case '3': case '4': case '5':
        case '6': case '7': case '8': case '9':
            dp_config_apply_preset(c, opt - '0');
            break;

        case 'f': c->frag_http = atoi(optarg); break;
        case 'e': c->frag_https = atoi(optarg); break;
        case 'k': c->frag_persistent = atoi(optarg); break;
        case 'r': c->host_replace = true; break;
        case 'm': c->host_case = true; break;
        case 's': c->host_nospace = true; c->method_space = true; break;
        case 'a': c->host_nospace = true; c->method_space = true; break;
        case 'p':
            LOGW("-p (block passive DPI) has no macOS equivalent: inbound "
                 "packets never reach dpiOS, so a forged RST cannot be "
                 "filtered. Ignoring.");
            break;

        case OPT_FRAG_SNI:     c->frag_sni = true; break;
        case OPT_RECORD_FRAG:    c->record_frag = true; break;
        case OPT_NO_RECORD_FRAG: c->record_frag = false; break;
        case OPT_DOH:            c->doh = true; break;
        case OPT_NO_DOH:         c->doh = false; break;
        case OPT_DOH_URL:
            strlcpy(c->doh_url, optarg, sizeof(c->doh_url));
            c->doh = true;
            break;
        case OPT_DOH_BOOTSTRAP:
            strlcpy(c->doh_bootstrap, optarg, sizeof(c->doh_bootstrap));
            break;
        case OPT_REVERSE_FRAG: c->reverse_frag = true; break;
        case OPT_IP_FRAG:      c->ip_frag = true; break;

        case OPT_FAKE:         c->fake_enable = true; break;
        case OPT_FAKE_SNI:
            strlcpy(c->fake_sni, optarg, sizeof(c->fake_sni));
            break;
        case OPT_FAKE_RESEND:
            c->fake_resend = atoi(optarg);
            if (c->fake_resend < 1) c->fake_resend = 1;
            break;
        case OPT_SET_TTL:
            c->fake_ttl = atoi(optarg);
            c->fake_enable = true;
            break;
        case OPT_AUTO_TTL:
            if (!parse_auto_ttl(optarg, c))
                return 2;
            c->fake_enable = true;
            break;
        case OPT_WRONG_CHKSUM:
            c->wrong_chksum = true; c->fake_enable = true;
            break;
        case OPT_WRONG_SEQ:
            c->wrong_seq = true; c->fake_enable = true;
            break;
        case OPT_SEQ_DELTA:
            c->wrong_seq_delta = (uint32_t)strtoul(optarg, NULL, 0);
            break;

        case OPT_PORT:
            if (!ports_reset) {
                /* an explicit --port replaces the 80/443 default */
                c->nports = 0;
                ports_reset = true;
            }
            if (!dp_config_add_port(c, atoi(optarg))) {
                LOGE("bad or duplicate port: %s", optarg);
                return 2;
            }
            break;
        case OPT_MAX_PAYLOAD: c->max_payload = atoi(optarg); break;
        case OPT_IPV6:        c->enable_ipv6 = true; break;
        case OPT_BLOCK_QUIC:  c->block_quic = true; break;
        case OPT_IFACE:       strlcpy(c->iface, optarg, sizeof(c->iface)); break;
        case OPT_INJECT:
            if (strcmp(optarg, "bpf") == 0) {
                c->inject_mode = INJECT_BPF;
            } else if (strcmp(optarg, "raw") == 0) {
                c->inject_mode = INJECT_RAW;
            } else {
                LOGE("--inject expects bpf or raw, got '%s'", optarg);
                return 2;
            }
            break;

        case OPT_BLACKLIST:
            strlcpy(c->blacklist_path, optarg, sizeof(c->blacklist_path));
            break;
        case OPT_WHITELIST:
            strlcpy(c->whitelist_path, optarg, sizeof(c->whitelist_path));
            break;

        case OPT_CHECK:   c->action = DP_ACTION_CHECK; break;
        case OPT_UNLOAD:  c->action = DP_ACTION_UNLOAD; break;
        case OPT_SYSLOG:  c->use_syslog = true; break;
        case OPT_NO_UI:   c->no_ui = true; break;
        case OPT_DRY_RUN: c->dry_run = true; break;
        case OPT_QUIET:   verbosity = -1; break;
        case 'v':         verbosity++; break;

        case 'V':
            printf("dpiOS %s\n", DPIOS_VERSION);
            return 1;
        case 'h':
            dp_usage(argv[0]);
            return 1;
        default:
            fprintf(stderr, "Try '%s --help'.\n", argv[0]);
            return 2;
        }
    }

    if (optind < argc) {
        LOGE("unexpected argument: %s", argv[optind]);
        return 2;
    }

    if (verbosity < 0)
        dp_log_setlevel(DP_ERR);
    else if (verbosity == 1)
        dp_log_setlevel(DP_DEBUG);
    else if (verbosity >= 2)
        dp_log_setlevel(DP_TRACE);

    /* Nothing selected at all: -5 is the sensible modern default. */
    if (c->action == DP_ACTION_RUN && c->preset == 0 &&
        !c->frag_http && !c->frag_https && !c->frag_persistent &&
        !c->host_replace && !c->host_case && !c->host_nospace &&
        !c->fake_enable) {
        LOGI("no options given, using preset -5");
        dp_config_apply_preset(c, 5);
    }

    if (c->frag_https == 0 && !c->frag_sni)
        c->frag_https = 2;

    return 0;
}
