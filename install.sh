#!/bin/bash
#
# dpiOS tek komutluk kurulum.
#
#   sudo ./install.sh
#   sudo ./install.sh discord.com baskasite.com     # kendi listenle test et
#
# Sırasıyla: derler, makineyi doğrular, engelin türünü teşhis eder, hangi
# preset'in işe yaradığını deneyerek bulur, servisi kurar ve sonucu raporlar.
#
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$REPO_DIR/build/dpios"
LABEL="com.dpios.daemon"
ANCHOR="com.apple/dpios"
PRESETS=(5 6 9 7)          # denenme sırası
CLEAN_DNS="1.1.1.1"

# Öntanımlı sınama listesi. Bu üç alan adı, geliştirme sırasında bir Türkiye
# operatörü üzerinde hem DNS hem DPI katmanında engelli ölçülmüş ve dpiOS ile
# açıldığı doğrulanmış servislerdir. Argüman verilirse liste değiştirilir.
if [[ $# -gt 0 ]]; then
    SITES=("$@")
else
    SITES=(discord.com roblox.com wattpad.com)
fi
CONTROL_SITE="example.com"   # her zaman açık olmalı, ölçüm referansı

# ---------------------------------------------------------------- görünüm --
#
# Animasyonlar gerçek terminale (fd 3) gider, log dosyasına değil. Böylece
# ekranda dönen spinner'ı görürsün ama /tmp/dpios-install.log içinde
# \r karakterlerinden oluşan bir çöp yığını olmaz.
#
# UTF-8 yoksa ${#dizge} karakter değil bayt sayar ve kutular şaşar.
export LC_ALL="${LC_ALL:-en_US.UTF-8}"

TTY=0; [[ -t 1 ]] && TTY=1

if [[ $TTY -eq 1 ]]; then
    R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
    GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[31m'; CYN=$'\033[36m'
    MAG=$'\033[35m'
else
    R=""; B=""; D=""; GRN=""; YLW=""; RED=""; CYN=""; MAG=""
fi

WIDTH=68
STEP_NO=0
STEP_TOTAL=6
SPIN_PID=""
SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)

hr()   { local i s=""; for ((i=0;i<WIDTH;i++)); do s="$s─"; done; printf '%s' "$s"; }
pad()  { local n=$1 i s=""; for ((i=0;i<n;i++)); do s="$s "; done; printf '%s' "$s"; }

# görünen kolon sayısı (UTF-8 baytları değil)
cols() { printf '%s' "$1" | awk '{n=0; for(i=1;i<=length($0);i++) n++; print n}'; }

# Dolguyu elle sayıyoruz: printf'in %-*s alan genişliği baytla ölçer, biz
# görünen kolonu istiyoruz.
box() {  # box "başlık" "alt satır"
    local t="$1" s="$2" inner=$((WIDTH-2))
    printf '%s╭%s╮%s\n' "$CYN" "$(hr)" "$R"
    printf '%s│%s %s%s%s%s %s│%s\n' "$CYN" "$R" "$B" "$t" "$R" \
           "$(pad $((inner-${#t})))" "$CYN" "$R"
    if [[ -n "$s" ]]; then
        printf '%s│%s %s%s%s%s %s│%s\n' "$CYN" "$R" "$D" "$s" "$R" \
               "$(pad $((inner-${#s})))" "$CYN" "$R"
    fi
    printf '%s╰%s╯%s\n' "$CYN" "$(hr)" "$R"
}

step()  { STEP_NO=$((STEP_NO+1))
          echo
          printf '%s%s[%d/%d]%s %s%s%s\n' "$MAG" "$B" "$STEP_NO" "$STEP_TOTAL" \
                 "$R" "$B" "$*" "$R"; }
ok()    { echo "    ${GRN}✓${R} $*"; }
warn()  { echo "    ${YLW}!${R} $*"; }
bad()   { echo "    ${RED}✗${R} $*"; }
info()  { echo "    ${D}$*${R}"; }

spin_start() {
    [[ $TTY -eq 1 ]] || { info "$1..."; return; }
    (
        trap 'exit 0' TERM
        local i=0
        while :; do
            printf '\r    %s%s%s %s' "$CYN" "${SPIN[i%10]}" "$R" "$1" >&3
            i=$((i+1))
            sleep 0.08
        done
    ) &
    SPIN_PID=$!
}

spin_stop() {
    [[ -n "$SPIN_PID" ]] || return 0
    kill "$SPIN_PID" 2>/dev/null
    wait "$SPIN_PID" 2>/dev/null
    SPIN_PID=""
    printf '\r\033[2K' >&3
}

bar() {  # bar mevcut toplam "mesaj"
    [[ $TTY -eq 1 ]] || return 0
    local cur=$1 tot=$2 msg=$3 w=22 i f=0
    [[ $tot -gt 0 ]] && f=$(( cur * w / tot ))
    local s=""
    for ((i=0;i<w;i++)); do
        if [[ $i -lt $f ]]; then s="$s█"; else s="$s░"; fi
    done
    printf '\r    %s%s%s  %s' "$CYN" "$s" "$R" "$msg" >&3
}
bar_done() { [[ $TTY -eq 1 ]] && printf '\r\033[2K' >&3; return 0; }

die()   { spin_stop; echo; echo "${RED}${B}Durduruldu:${R} $*"; exit 1; }
trap 'spin_stop' EXIT INT TERM

# ------------------------------------------------------------- ön kontrol --
[[ "$(uname -s)" == "Darwin" ]] || die "Bu script sadece macOS içindir."

# Klasör kontrolü root kontrolünden önce: sudo unutulmuş olsa bile kullanıcı
# önce asıl sorunu görsün.
if [[ ! -f "$REPO_DIR/Makefile" || ! -d "$REPO_DIR/src" ]]; then
    die "Bu script dpiOS klasörünün içinden çalıştırılmalı.
    cd ~/dpiOS && sudo bash install.sh"
fi

[[ $EUID -eq 0 ]] || die "Root yetkisi gerekiyor: sudo bash install.sh"

# Her şeyi bir dosyaya da yaz: bir yerde takılırsan tek dosyayı paylaşman yeter.
# fd 3 gerçek terminale bakar; spinner oraya yazılır, log temiz kalır.
TRANSCRIPT="/tmp/dpios-install.log"
exec 3>&1
exec > >(tee "$TRANSCRIPT") 2>&1

echo
box "dpiOS  ·  DPI aşma aracı" \
    "$(sw_vers -productName) $(sw_vers -productVersion) · $(uname -m) · kayıt: $TRANSCRIPT"

# ------------------------------------------------------------------ derle --
step "Derleniyor"
if ! xcode-select -p >/dev/null 2>&1; then
    die "Xcode Command Line Tools kurulu değil: xcode-select --install"
fi
spin_start "kaynak derleniyor"
make -C "$REPO_DIR" >/tmp/dpios-build.log 2>&1
MAKE_RC=$?
spin_stop
if [[ $MAKE_RC -ne 0 ]]; then
    tail -25 /tmp/dpios-build.log
    die "Derleme başarısız. Tam log: /tmp/dpios-build.log"
fi
ok "build/dpios hazır ($(cd "$REPO_DIR" && git rev-parse --short HEAD 2>/dev/null || echo yerel))"

# --------------------------------------------------- çalışan örneği durdur --
launchctl bootout "system/${LABEL}" 2>/dev/null
pkill -x dpios 2>/dev/null
sleep 0.5
pfctl -a "$ANCHOR" -F all >/dev/null 2>&1

# ------------------------------------------------------- makineyi doğrula --
step "Makine doğrulanıyor"
spin_start "utun, pf ve BPF deneniyor"
CHECK_OUT="$("$BIN" --check 2>&1)"
CHECK_RC=$?
spin_stop
echo "$CHECK_OUT" | sed 's/^/    /'
if [[ $CHECK_RC -ne 0 ]]; then
    echo
    if echo "$CHECK_OUT" | grep -q "anchor com.apple"; then
        info "Önerilen: sudo pfctl -f /etc/pf.conf"
    fi
    if echo "$CHECK_OUT" | grep -q "gateway hwaddr"; then
        info "Önerilen: ping -c2 \$(route -n get default | awk '/gateway/{print \$2}')"
    fi
    die "Self-test başarısız. Yukarıdaki FAIL satırları giderilmeden devam edilemez."
fi

# ------------------------------------------------------------ DNS teşhisi --
step "Engelin türü tespit ediliyor"

# Sistemin verdiği cevabı, şifreli DNS'in (DoH) verdiği gerçek cevapla
# karşılaştırırız. Düz DNS'te başka bir sunucu denemenin anlamı yok: bu ISS
# engelli alan adları için sorguyu hangi sunucuya giderse gitsin araya girip
# düşürüyor (ölçüldü: 1.1.1.1'e UDP cevapsız, TCP'de RST).
dns_system() { dscacheutil -q host -a name "$1" 2>/dev/null \
                 | awk '/^ip_address:/{print $2; exit}'; }
dns_doh()    { curl -sS --max-time 10 -H 'accept: application/dns-json' \
                 "https://cloudflare-dns.com/dns-query?name=$1&type=A" 2>/dev/null \
                 | grep -o '"data":"[0-9][0-9.]*"' | cut -d'"' -f4; }

#
# Adres karşılaştırmak göründüğü kadar basit değil. İki tuzak var:
#
#   1. Büyük siteler her sorguda farklı adres döndürür (discord.com 6,
#      google.com 2 A kaydı), o yüzden tek adres karşılaştırması yanlış alarm
#      verir. Kümede arıyoruz.
#   2. Coğrafi DNS kullanan siteler için kümeler de tutmaz: ISS'in
#      çözümleyicisi ile Cloudflare farklı ama ikisi de geçerli adres döndürür.
#      google.com tam olarak böyle.
#
# O yüzden asıl soruyu soruyoruz: sistemin verdiği adres gerçekten o siteyi
# sunuyor mu? Sunuyorsa hangi adres olduğu önemli değil.
#
# 0 = yönlendiriliyor · 1 = temiz · 2 = karar verilemedi

# sistemin cevabı gerçek adres kümesinin içinde mi (kesin ama dar)
dns_matches() {
    local sys real
    sys="$(dns_system "$1")"
    real="$(dns_doh "$1")"
    [[ -z "$real" ]] && return 2
    [[ -z "$sys" ]] && return 0
    printf '%s\n' "$real" | grep -qx "$sys" && return 1 || return 0
}

dns_verdict() {
    dns_matches "$1"
    local m=$?
    [[ $m -ne 0 ]] && return $m          # temiz ya da karar verilemedi

    # Küme dışı bir adres. Yönlendirme mi, yoksa sadece başka bir sunucu mu?
    local sys
    sys="$(dns_system "$1")"
    [[ -z "$sys" ]] && return 0
    if curl -sS --max-time 8 -o /dev/null \
            --resolve "$1:443:$sys" "https://$1/" 2>/dev/null; then
        return 1                          # siteyi sunuyor, sorun yok
    fi
    return 0
}

DNS_HIJACKED=0
for site in "${SITES[@]}"; do
    spin_start "$site sorgulanıyor"
    dns_verdict "$site"; v=$?
    spin_stop
    case $v in
        0) bad  "$site — sistem $(dns_system "$site") diyor, gerçek adresler arasında yok (DNS yönlendirmesi)"
           DNS_HIJACKED=1 ;;
        1) ok   "$site — DNS temiz ($(dns_system "$site"))" ;;
        *) warn "$site — şifreli DNS cevap vermedi, karşılaştırma yapılamadı" ;;
    esac
done

#
# DNS düzeltmesi: /etc/hosts.
#
# Daha önce burada bir yapılandırma profili (DoH) açılıyordu, ama profil
# kurulumu macOS'un onay ekranına bağlı ve "VPN ve Aygıt Yönetimi" altında
# sessizce reddedilebiliyor. Onun yerine adresleri şifreli DNS ile burada,
# kurulum sırasında çözüp doğrudan /etc/hosts'a yazıyoruz: hiçbir onay
# ekranı, hiçbir profil, hiçbir arka plan servisi yok.
#
HOSTS_BEGIN="# BEGIN dpiOS"
HOSTS_END="# END dpiOS"

hosts_strip() {
    [[ -f /etc/hosts ]] || return 0
    grep -q "^${HOSTS_BEGIN}$" /etc/hosts 2>/dev/null || return 0
    awk -v b="$HOSTS_BEGIN" -v e="$HOSTS_END" '
        $0 == b { skip = 1; next }
        $0 == e { skip = 0; next }
        !skip   { print }
    ' /etc/hosts > /tmp/dpios-hosts.new && cat /tmp/dpios-hosts.new > /etc/hosts
    rm -f /tmp/dpios-hosts.new
}

# Bir alan adının bütün A kayıtlarını şifreli DNS üzerinden al
doh_all() {
    curl -sS --max-time 10 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=$1&type=A" 2>/dev/null \
        | grep -o '"data":"[0-9][0-9.]*"' | cut -d'"' -f4
}

#
# Tercih edilen çözüm: dpiOS'un kendi şifreli DNS çözümleyicisi.
#
# /etc/hosts sadece önceden bildiğimiz isimleri kapsayabilir. Oysa filtre
# wildcard çalışıyor (ölçüldü: var olmayan bir alt alan adı bile engel
# sayfasına gidiyor) ve masaüstü uygulamaları çalışma anında öğrendikleri
# isimleri çözüyor - gateway.us-east1-b.discord.gg gibi. Bunları statik bir
# dosyaya yazmak mümkün değil, o yüzden gerçek bir çözümleyici gerekiyor.
#
DOH_ARGS=""
if [[ $DNS_HIJACKED -eq 1 ]]; then
    echo
    step "Şifreli DNS deneniyor"
    spin_start "çözümleyici başlatılıyor"
    "$BIN" -5 --doh --no-ui >/tmp/dpios-doh.log 2>&1 &
    dohpid=$!
    sleep 3
    spin_stop

    if kill -0 "$dohpid" 2>/dev/null; then
        dscacheutil -flushcache 2>/dev/null
        killall -HUP mDNSResponder 2>/dev/null
        sleep 1

        good=0
        for site in "${SITES[@]}"; do
            dns_matches "$site"; [[ $? -eq 1 ]] && good=$((good+1))
        done

        kill -TERM "$dohpid" 2>/dev/null
        wait "$dohpid" 2>/dev/null
        pfctl -a "$ANCHOR" -F all >/dev/null 2>&1

        if [[ $good -eq ${#SITES[@]} ]]; then
            ok "şifreli DNS çalışıyor — alt alan adları da kapsanıyor"
            info "masaüstü uygulamaları da bu çözümleyiciyi kullanır"
            DOH_ARGS="--doh"
            DNS_HIJACKED=0
        else
            warn "şifreli DNS beklendiği gibi cevap vermedi, /etc/hosts'a düşülüyor"
        fi
    else
        warn "şifreli DNS çözümleyicisi başlatılamadı:"
        tail -5 /tmp/dpios-doh.log | sed 's/^/        /'
        info "/etc/hosts yöntemine düşülüyor (sadece sabit isimleri kapsar)"
    fi
fi

if [[ $DNS_HIJACKED -eq 1 ]]; then
    echo
    info "DNS engeli /etc/hosts üzerinden aşılacak: adresler şifreli DNS ile"
    info "çözülüp doğrudan yazılıyor. Onay ekranı yok."

    # Discord tek bir alan adı değil; uygulamanın çalışması için yanındaki
    # birkaç alan adı da lazım.
    TARGETS=("${SITES[@]}")
    for s in "${SITES[@]}"; do
        case "$s" in
            *discord*)
                TARGETS+=(discord.com discord.gg discordapp.com
                          cdn.discordapp.com media.discordapp.net
                          gateway.discord.gg
                          images-ext-1.discordapp.net status.discord.com)
                ;;
        esac
    done

    [[ -f /etc/hosts.dpios.bak ]] || cp /etc/hosts /etc/hosts.dpios.bak 2>/dev/null
    hosts_strip

    ENTRIES=()
    SEEN=" "
    for host in "${TARGETS[@]}"; do
        case "$SEEN" in *" $host "*) continue ;; esac
        SEEN="$SEEN$host "
        ip="$(doh_all "$host" | head -1)"
        if [[ -n "$ip" ]]; then
            ENTRIES+=("$ip	$host")
            ok "$host -> $ip"
        else
            warn "$host — şifreli DNS cevap vermedi, atlandı"
        fi
    done

    if [[ ${#ENTRIES[@]} -gt 0 ]]; then
        {
            echo "$HOSTS_BEGIN"
            echo "# dpiOS tarafından eklendi. Kaldırmak için:"
            echo "#   sudo bash scripts/uninstall-service.sh"
            printf '%s\n' "${ENTRIES[@]}"
            echo "$HOSTS_END"
        } >> /etc/hosts
        ok "/etc/hosts güncellendi (${#ENTRIES[@]} kayıt), yedek: /etc/hosts.dpios.bak"

        dscacheutil -flushcache 2>/dev/null
        killall -HUP mDNSResponder 2>/dev/null
        sleep 1

        DNS_HIJACKED=0
        for site in "${SITES[@]}"; do
            dns_matches "$site"
            if [[ $? -eq 1 ]]; then
                ok "$site — DNS artık temiz"
            else
                warn "$site — DNS hâlâ yönlendiriliyor"
                DNS_HIJACKED=1
            fi
        done

        #
        # IPv6 kapısı.
        #
        # Bu ISS engelli alan adları için sahte bir AAAA kaydı uyduruyor
        # (ölçüldü: discord.com'un gerçek AAAA kaydı yok, sistem yine de
        # 2a01:358:... döndürüyor). macOS IPv6'yı tercih ettiği için, /etc/hosts'a
        # yazdığımız IPv4 adresi işe yaramadan trafik engel sayfasına gidebilir.
        # Sadece gerçekten böyle bir kayıt kaldıysa müdahale ediyoruz.
        LEFTOVER6=""
        for site in "${SITES[@]}"; do
            v6="$(dscacheutil -q host -a name "$site" 2>/dev/null \
                  | awk '/^ipv6_address:/{print $2; exit}')"
            real6="$(curl -sS --max-time 8 -H 'accept: application/dns-json' \
                     "https://cloudflare-dns.com/dns-query?name=${site}&type=AAAA" \
                     2>/dev/null | grep -o '"type":28' | head -1)"
            if [[ -n "$v6" && -z "$real6" ]]; then
                LEFTOVER6="$site"
                break
            fi
        done

        if [[ -n "$LEFTOVER6" ]]; then
            warn "$LEFTOVER6 için sahte bir IPv6 kaydı dönüyor (gerçek AAAA kaydı yok)."
            DEV6="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
            SVC6="$(networksetup -listnetworkserviceorder 2>/dev/null \
                    | grep -B1 "Device: ${DEV6})" | head -1 | sed 's/^([0-9]*) //')"
            if [[ -n "$SVC6" ]] && networksetup -setv6off "$SVC6" 2>/dev/null; then
                ok "IPv6 kapatıldı ($SVC6) — trafik IPv4 üzerinden gidecek"
                info "Geri açmak için: sudo networksetup -setv6automatic \"$SVC6\""
                dscacheutil -flushcache 2>/dev/null
                killall -HUP mDNSResponder 2>/dev/null
                sleep 1
            else
                warn "IPv6 kapatılamadı. Elle uygulanabilir: sudo networksetup -setv6off \"Wi-Fi\""
            fi
        fi
    else
        warn "Hiçbir adres çözülemedi; şifreli DNS'e de erişilemiyor olabilir."
    fi
fi

# ------------------------------------------------------------- site testi --
# curl çıkış kodları: 0 açıldı · 35/56 bağlantı sıfırlandı (DPI) ·
# 28 zaman aşımı · 7 bağlanamadı (IP engeli) · 6 çözümlenemedi (DNS)
probe() {
    local host="$1" out rc
    out="$(curl -sS -o /dev/null -w '%{http_code}' \
            --max-time 10 --connect-timeout 6 --no-keepalive \
            -A 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' \
            "https://${host}/" 2>&1)"
    rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "acik:$out"
    else
        case $rc in
            35|56|52) echo "dpi:$rc" ;;
            60|51)    echo "sertifika:$rc" ;;
            28)       echo "zamanasimi:$rc" ;;
            7)        echo "ipengeli:$rc" ;;
            6)        echo "dns:$rc" ;;
            *)        echo "hata:$rc" ;;
        esac
    fi
}

describe() {
    case "${1%%:*}" in
        acik)       echo "${GRN}açıldı${R}" ;;
        dpi)        echo "${RED}bağlantı sıfırlandı (DPI)${R}" ;;
        sertifika)  echo "${RED}sertifika hatası (DNS yönlendirmesi)${R}" ;;
        zamanasimi) echo "${RED}zaman aşımı${R}" ;;
        ipengeli)   echo "${RED}bağlanamadı (IP engeli)${R}" ;;
        dns)        echo "${RED}isim çözümlenemedi${R}" ;;
        *)          echo "${RED}hata (curl ${1##*:})${R}" ;;
    esac
}

score_sites() {   # kaç site açıldı
    local n=0
    for s in "${SITES[@]}"; do
        [[ "$(probe "$s")" == acik:* ]] && n=$((n+1))
    done
    echo "$n"
}

step "Önce dpiOS olmadan ölçüm"
BASELINE=0
for site in "${SITES[@]}"; do
    spin_start "$site deneniyor"
    res="$(probe "$site")"
    spin_stop
    [[ "$res" == acik:* ]] && BASELINE=$((BASELINE+1))
    echo "    $site: $(describe "$res")"
done
ctrl="$(probe "$CONTROL_SITE")"
if [[ "$ctrl" != acik:* ]]; then
    warn "Kontrol sitesi ($CONTROL_SITE) da açılmıyor — internet bağlantında"
    warn "genel bir sorun olabilir. Sonuçlar yanıltıcı olacaktır."
fi

if [[ $BASELINE -eq ${#SITES[@]} ]]; then
    echo
    ok "Bütün siteler dpiOS olmadan zaten açılıyor."
    info "Müdahale gerektiren bir engel yok. Yine de kurmak için:"
    info "  sudo ./scripts/install-service.sh -5"
    exit 0
fi

# ---------------------------------------------------- preset'i deneyerek bul
step "Hangi ayar işe yarıyor, deneniyor"
info "Her ayar için dpiOS kısa süre çalıştırılıp siteler tekrar denenecek."
PTOTAL=${#PRESETS[@]}
PDONE=0

BEST_PRESET=""
BEST_SCORE=$BASELINE

for p in "${PRESETS[@]}"; do
    bar $PDONE $PTOTAL "preset -$p deneniyor"
    "$BIN" "-$p" $DOH_ARGS --no-ui >/tmp/dpios-try.log 2>&1 &
    dpid=$!
    sleep 2

    if ! kill -0 "$dpid" 2>/dev/null; then
        warn "preset -$p başlatılamadı:"
        tail -3 /tmp/dpios-try.log | sed 's/^/        /'
        continue
    fi

    dscacheutil -flushcache 2>/dev/null
    n="$(score_sites)"
    PDONE=$((PDONE+1))
    bar $PDONE $PTOTAL "preset -$p denendi"

    kill -TERM "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null
    pfctl -a "$ANCHOR" -F all >/dev/null 2>&1

    # motor gerçekten paket gördü mü?
    seen="$(grep -o 'tls [0-9]*' /tmp/dpios-try.log | tail -1 | awk '{print $2}')"
    seen="${seen:-0}"

    bar_done
    if [[ $n -gt $BEST_SCORE ]]; then
        ok "preset -$p → ${#SITES[@]} siteden $n tanesi açıldı ${D}(motor $seen TLS isteği işledi)${R}"
        BEST_SCORE=$n
        BEST_PRESET=$p
        [[ $n -eq ${#SITES[@]} ]] && break
    else
        info "preset -$p → $n açıldı (motor $seen TLS isteği işledi)"
    fi
done

# ------------------------------------------------------------------ sonuç --
if [[ -z "$BEST_PRESET" ]]; then
    step "Sonuç"
    bad "Hiçbir preset engeli aşamadı."
    echo
    # motor hiç paket görmediyse sorun dpiOS'un kendisinde
    last_seen="$(grep -o 'tls [0-9]*' /tmp/dpios-try.log | tail -1 | awk '{print $2}')"
    if [[ -z "$last_seen" || "$last_seen" == "0" ]]; then
        bad "Motor hiç TLS isteği görmedi — trafik dpiOS'a hiç uğramıyor."
        info "pf yönlendirmesi çalışmıyor. Teşhis için:"
        info "  sudo $BIN -5 -vv"
        info "  sudo pfctl -a $ANCHOR -s rules"
    else
        info "Motor trafiği görüyor ve işliyor ama engel aşılamıyor."
        info "Bu, engelin SNI tabanlı DPI olmadığı anlamına gelir — muhtemelen"
        info "IP seviyesinde engelleme var ve bunu ancak VPN/proxy aşar."
        info "Tam teşhis için: sudo $BIN -5 -vv"
    fi
    pfctl -a "$ANCHOR" -F all >/dev/null 2>&1
    exit 1
fi

step "Kuruluyor (preset -$BEST_PRESET)"
spin_start "binary ve servis yerleştiriliyor"
install -d /usr/local/bin
install -m 0755 "$BIN" /usr/local/bin/dpios
ok "/usr/local/bin/dpios"

# Servis bir kolaylık, motorun kendisi değil. Kurulamazsa her şeyi iptal etmek
# yerine uyarıp devam ediyoruz; dpiOS elle çalıştırıldığında yine çalışır.
SERVICE_OK=1
if bash "$REPO_DIR/scripts/install-service.sh" --skip-check \
        "-$BEST_PRESET" $DOH_ARGS >/tmp/dpios-service.log 2>&1; then
    spin_stop
    ok "launchd servisi kuruldu, açılışta otomatik başlayacak"
else
    spin_stop
    SERVICE_OK=0
    warn "launchd servisi kurulamadı. Sebep:"
    tail -12 /tmp/dpios-service.log | sed 's/^/        /'
    echo
    info "Motor çalışmaya devam eder; yalnızca açılışta otomatik başlamaz."
    info "Elle başlatmak için:    sudo dpios -$BEST_PRESET $DOH_ARGS"
    info "Tam log:                /tmp/dpios-service.log"
    # Servis yoksa da çalışsın: bu terminal kapanınca ölmemesi için nohup.
    nohup /usr/local/bin/dpios "-$BEST_PRESET" $DOH_ARGS --no-ui \
        >/tmp/dpios-manual.log 2>&1 &
    disown 2>/dev/null || true
    sleep 2
fi

sleep 2
dscacheutil -flushcache 2>/dev/null

step "Son durum"
final=0
for site in "${SITES[@]}"; do
    spin_start "$site tekrar deneniyor"
    res="$(probe "$site")"
    spin_stop
    [[ "$res" == acik:* ]] && final=$((final+1))
    echo "    $site: $(describe "$res")"
done

echo
if [[ $final -eq ${#SITES[@]} ]]; then
    if [[ $SERVICE_OK -eq 1 ]]; then
        echo "${GRN}${B}Tamam.${R} dpiOS preset -$BEST_PRESET ile çalışıyor ve açılışta başlayacak."
    else
        echo "${GRN}${B}Çalışıyor.${R} dpiOS preset -$BEST_PRESET ile açık, ama servis"
        echo "kurulamadığı için ${B}bilgisayarı yeniden başlatınca durur${R}."
    fi
else
    echo "${YLW}${B}Kısmen çalışıyor.${R} ${#SITES[@]} siteden $final tanesi açıldı."
fi

echo
if [[ $SERVICE_OK -eq 1 ]]; then
    echo "  ${D}loglar${R}    tail -f /var/log/dpios.log"
    echo "  ${D}durdur${R}    sudo launchctl bootout system/${LABEL}"
    echo "  ${D}kaldır${R}    sudo ./scripts/uninstall-service.sh"
else
    echo "  ${D}başlat${R}    sudo dpios -$BEST_PRESET $DOH_ARGS"
    echo "  ${D}durdur${R}    sudo pkill -x dpios"
    echo "  ${D}servisi tekrar dene${R}"
    echo "            sudo bash scripts/install-service.sh -$BEST_PRESET"
fi
echo "  ${D}acil${R}      sudo pfctl -a ${ANCHOR} -F all"
echo
