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

# test edilecek siteler
if [[ $# -gt 0 ]]; then
    SITES=("$@")
else
    SITES=(discord.com)
fi
CONTROL_SITE="example.com"   # her zaman açık olmalı, ölçüm referansı

# ---------------------------------------------------------------- görünüm --
if [[ -t 1 ]]; then
    R=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
    GRN=$'\033[32m'; YLW=$'\033[33m'; RED=$'\033[31m'; CYN=$'\033[36m'
else
    R=""; B=""; D=""; GRN=""; YLW=""; RED=""; CYN=""
fi

step()  { echo; echo "${CYN}${B}==>${R} ${B}$*${R}"; }
ok()    { echo "    ${GRN}✓${R} $*"; }
warn()  { echo "    ${YLW}!${R} $*"; }
bad()   { echo "    ${RED}✗${R} $*"; }
info()  { echo "    ${D}$*${R}"; }
die()   { echo; echo "${RED}${B}Durduruldu:${R} $*"; exit 1; }

# ------------------------------------------------------------- ön kontrol --
[[ "$(uname -s)" == "Darwin" ]] || die "Bu script sadece macOS içindir."

# Klasör kontrolü root kontrolünden önce: sudo unutulmuş olsa bile kullanıcı
# önce asıl sorunu görsün.
if [[ ! -f "$REPO_DIR/Makefile" || ! -d "$REPO_DIR/src" ]]; then
    die "Bu script dpiOS klasörünün içinden çalıştırılmalı.
    cd ~/dpiOS && sudo bash install.sh"
fi

[[ $EUID -eq 0 ]] || die "Root gerekiyor. Şunu çalıştır: sudo bash install.sh"

echo
echo "${B}dpiOS kurulumu${R}"
echo "${D}$(sw_vers -productName) $(sw_vers -productVersion) · $(uname -m)${R}"

# ------------------------------------------------------------------ derle --
step "Derleniyor"
if ! xcode-select -p >/dev/null 2>&1; then
    die "Xcode Command Line Tools kurulu değil. Şunu çalıştır: xcode-select --install"
fi
if ! make -C "$REPO_DIR" >/tmp/dpios-build.log 2>&1; then
    tail -25 /tmp/dpios-build.log
    die "Derleme başarısız. Tam log: /tmp/dpios-build.log"
fi
ok "build/dpios hazır"

# --------------------------------------------------- çalışan örneği durdur --
launchctl bootout "system/${LABEL}" 2>/dev/null
pkill -x dpios 2>/dev/null
sleep 0.5
pfctl -a "$ANCHOR" -F all >/dev/null 2>&1

# ------------------------------------------------------- makineyi doğrula --
step "Makine doğrulanıyor"
CHECK_OUT="$("$BIN" --check 2>&1)"
CHECK_RC=$?
echo "$CHECK_OUT" | sed 's/^/    /'
if [[ $CHECK_RC -ne 0 ]]; then
    echo
    if echo "$CHECK_OUT" | grep -q "anchor com.apple"; then
        info "Denenecek: sudo pfctl -f /etc/pf.conf"
    fi
    if echo "$CHECK_OUT" | grep -q "gateway hwaddr"; then
        info "Denenecek: ping -c2 \$(route -n get default | awk '/gateway/{print \$2}')"
    fi
    die "Self-test başarısız. Yukarıdaki FAIL satırlarını düzeltmeden devam edemeyiz."
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
                 | grep -o '"data":"[0-9][0-9.]*"' | head -1 | cut -d'"' -f4; }

DNS_HIJACKED=0
for site in "${SITES[@]}"; do
    sys="$(dns_system "$site")"
    real="$(dns_doh "$site")"
    if [[ -z "$real" ]]; then
        warn "$site — şifreli DNS cevap vermedi, karşılaştırma yapılamadı"
    elif [[ -z "$sys" ]]; then
        bad "$site — sistem DNS'i hiç cevap vermiyor (DNS ile engelleniyor)"
        DNS_HIJACKED=1
    elif [[ "$sys" != "$real" ]]; then
        bad "$site — sistem $sys diyor, gerçeği $real (DNS yönlendirmesi)"
        DNS_HIJACKED=1
    else
        ok "$site — DNS temiz ($sys)"
    fi
done

if [[ $DNS_HIJACKED -eq 1 ]]; then
    echo
    warn "DNS seviyesinde engel var ve dpiOS bunu çözemez — paket parçalama"
    warn "TLS el sıkışmasına müdahale eder, DNS sorgusuna değil."
    echo
    info "Çözüm: şifreli DNS (DoH). Depoda hazır profil var."
    info "Başka bir DNS sunucusu yazmak İŞE YARAMAZ; bu ISS engelli alan"
    info "adları için sorguyu hangi sunucuya gitse de düşürüyor."
    echo
    PROFILE="$REPO_DIR/profiles/dpios-encrypted-dns.mobileconfig"
    if [[ -f "$PROFILE" ]]; then
        echo "    Profili şimdi açayım mı? (Sistem Ayarları'ndan onaylaman gerekir) [E/h] "
        read -r -t 30 answer </dev/tty || answer="e"
        if [[ -z "$answer" || "$answer" =~ ^[EeYy] ]]; then
            sudo -u "${SUDO_USER:-$USER}" open "$PROFILE" 2>/dev/null \
                && ok "Profil açıldı — Sistem Ayarları > Genel > Aygıt Yönetimi'nden onayla" \
                || warn "Profil açılamadı. Elle: open \"$PROFILE\""
            echo
            echo "    Onayladıktan sonra Enter'a bas (atlamak için Ctrl-C)... "
            read -r -t 300 _ </dev/tty || true
            dscacheutil -flushcache 2>/dev/null
            killall -HUP mDNSResponder 2>/dev/null
            sleep 1
            for site in "${SITES[@]}"; do
                if [[ "$(dns_system "$site")" == "$(dns_doh "$site")" ]]; then
                    ok "$site — DNS artık temiz"
                    DNS_HIJACKED=0
                else
                    warn "$site — DNS hâlâ yönlendiriliyor, profil etkin değil"
                fi
            done
        fi
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
    res="$(probe "$site")"
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
    info "Test edecek bir engel yok. Yine de kurmak istersen:"
    info "  sudo ./scripts/install-service.sh -5"
    exit 0
fi

# ---------------------------------------------------- preset'i deneyerek bul
step "Hangi preset işe yarıyor, deneniyor"
info "Her preset için dpiOS kısa süre çalıştırılıp siteler tekrar denenecek."

BEST_PRESET=""
BEST_SCORE=$BASELINE

for p in "${PRESETS[@]}"; do
    "$BIN" "-$p" --no-ui >/tmp/dpios-try.log 2>&1 &
    dpid=$!
    sleep 2

    if ! kill -0 "$dpid" 2>/dev/null; then
        warn "preset -$p başlatılamadı:"
        tail -3 /tmp/dpios-try.log | sed 's/^/        /'
        continue
    fi

    dscacheutil -flushcache 2>/dev/null
    n="$(score_sites)"

    kill -TERM "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null
    pfctl -a "$ANCHOR" -F all >/dev/null 2>&1

    # motor gerçekten paket gördü mü?
    seen="$(grep -o 'tls [0-9]*' /tmp/dpios-try.log | tail -1 | awk '{print $2}')"
    seen="${seen:-0}"

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
        info "Yani pf yönlendirmesi çalışmıyor. Şunu çalıştırıp çıktıyı paylaş:"
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
install -d /usr/local/bin
install -m 0755 "$BIN" /usr/local/bin/dpios
ok "/usr/local/bin/dpios"

"$REPO_DIR/scripts/install-service.sh" "-$BEST_PRESET" >/tmp/dpios-service.log 2>&1 \
    && ok "launchd servisi kuruldu, açılışta otomatik başlayacak" \
    || { tail -10 /tmp/dpios-service.log | sed 's/^/    /'; die "Servis kurulamadı."; }

sleep 2
dscacheutil -flushcache 2>/dev/null

step "Son durum"
final=0
for site in "${SITES[@]}"; do
    res="$(probe "$site")"
    [[ "$res" == acik:* ]] && final=$((final+1))
    echo "    $site: $(describe "$res")"
done

echo
if [[ $final -eq ${#SITES[@]} ]]; then
    echo "${GRN}${B}Tamam.${R} dpiOS preset -$BEST_PRESET ile çalışıyor ve açılışta başlayacak."
else
    echo "${YLW}${B}Kısmen çalışıyor.${R} ${#SITES[@]} siteden $final tanesi açıldı."
fi
echo
echo "  ${D}loglar${R}    tail -f /var/log/dpios.log"
echo "  ${D}durdur${R}    sudo launchctl bootout system/${LABEL}"
echo "  ${D}kaldır${R}    sudo ./scripts/uninstall-service.sh"
echo "  ${D}acil${R}      sudo pfctl -a ${ANCHOR} -F all"
echo
