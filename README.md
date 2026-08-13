# dpiOS

GoodbyeDPI'ın macOS (Apple Silicon) karşılığı. DPI (Deep Packet Inspection)
tabanlı erişim engellerini, giden TLS el sıkışmasını yeniden çerçeveleyerek,
paketleri parçalayarak ve sahte paketler enjekte ederek aşar.

- **Kernel extension gerektirmez.** Apple Silicon'da kext yolu pratikte kapalı;
  dpiOS bunun yerine `pf` + `utun` + `/dev/bpf` üçlüsünü kullanıyor.
- **Apple Developer hesabı gerektirmez.** Network Extension'a, imzaya,
  entitlement'a ihtiyaç yok. Sadece `sudo`.
- **GoodbyeDPI ile aynı preset numaraları** (`-1`…`-9`), aynı bayrak isimleri.
- Tek bir C binary'si, harici bağımlılık yok. `launchd` servisi olarak kurulur.

```bash
git clone https://github.com/ahmethasmerdogan/dpiOS.git
cd dpiOS
sudo ./install.sh
```

---

## İçindekiler

- [Engel nasıl çalışıyor](#engel-nasıl-çalışıyor)
- [dpiOS nasıl çalışıyor](#dpios-nasıl-çalışıyor)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Servis olarak çalıştırma](#servis-olarak-çalıştırma)
- [Sorun giderme](#sorun-giderme)
- [Sınırlar](#sınırlar)
- [Geliştirme](#geliştirme)

---

## Engel nasıl çalışıyor

Aşağıdakiler tahmin değil, bir Türk ISS'i üzerinde ölçüldü. Engel **iki ayrı
katmanda** çalışıyor ve ikisi de aşılmadan site açılmıyor.

### 1. DNS katmanı

Sistem `discord.com` için engel sayfasının IP'sini döndürüyor:

| kaynak | cevap |
|--------|-------|
| sistem çözümleyicisi | `195.175.254.2` (engel sayfası) |
| gerçek (DoH ile) | `162.159.137.232` … |

Kritik nokta: **DNS sunucusunu değiştirmek işe yaramıyor.** Sorgunun kendisi
araya giriliyor ve bu, alan adına özel:

| sorgu | `example.com` | `discord.com` |
|-------|---------------|---------------|
| `1.1.1.1` UDP/53 | ✅ cevap | ❌ zaman aşımı |
| `1.1.1.1` TCP/53 | ✅ cevap | ❌ RST |
| DoH (şifreli) | ✅ | ✅ **gerçek IP** |

Büyük/küçük harf karıştırma (DNS 0x20) da denendi, filtre harfe duyarsız.
Yani çözüm tek: **şifreli DNS**. Depoda hazır profil var, `install.sh` gerekli
olduğunda açıyor.

### 2. DPI katmanı

DNS düzeltilip gerçek IP'ye bağlanıldığında bile TLS el sıkışması ~14 ms'de
RST yiyor. Bu DPI **TCP akışını yeniden birleştirdikten sonra** inceliyor, yani
klasik parçalama numaraları çalışmıyor:

| teknik | sonuç |
|--------|-------|
| tek parça (kontrol) | RST |
| TCP'de 2. bayttan bölme | RST |
| TCP'de SNI ortasından bölme | RST |
| SNI'ı karışık harfle yazma | RST |
| SNI eklentisini eklenti listesinin sonuna alma | RST |
| **TLS kayıt katmanında bölme** | **ServerHello** ✅ |

Çalışan tek teknik: ClientHello'yu **iki TLS kaydına** bölmek. Bir handshake
mesajının birden fazla kayda yayılması TLS'te geçerlidir; sadece ilk kaydı
ayrıştıran bir denetleyici hiçbir zaman bütün ClientHello'yu göremez.

---

## dpiOS nasıl çalışıyor

GoodbyeDPI Windows'ta WinDivert sürücüsüyle paketleri çekirdek seviyesinde
yakalar. macOS'ta WinDivert yok. dpiOS aynı işi macOS'un kendi parçalarıyla
yapıyor:

```
  uygulama (Safari, Discord, curl…)
        │
        ▼
  kernel TCP/IP yığını          ← kaynak IP burada seçilir: 192.168.1.x
        │
        ▼
  pf: "route-to (utunN)"        ← sadece TCP 80/443, sadece internete giden
        │
        ▼
  utun cihazı  ──────────────▶  dpios (userspace)
                                   │  ClientHello'yu iki TLS kaydına böl
                                   │  TCP segmentine böl, sırasını ters çevir
                                   │  sahte paket üret (düşük TTL / bozuk checksum)
                                   │  HTTP header'larını değiştir
                                   ▼
                                /dev/bpf ──▶ en0 ──▶ internet

  dönüş trafiği: en0 ──▶ kernel   (dpios'a hiç uğramaz)
```

Üç tasarım kararı bu mimariyi belirliyor:

**1. Varsayılan rota değiştirilmiyor.** `pf route-to` ile sadece ilgilendiğimiz
trafik utun'a çevriliyor. Kaynak IP adresi değişmediği için NAT yazmaya gerek
yok.

**2. Dönüş trafiği bize uğramıyor.** Kernel soketi 4'lü demeti zaten tanıyor.
Throughput için çok iyi; karşılığında gelen paketleri filtreleyemiyoruz
(bkz. [Sınırlar](#sınırlar)).

**3. Paket uzunluğu asla değişmiyor.** Kernel, o sequence numarasında tam N bayt
gönderdiğini varsayıyor. Bir bayt eksik/fazla göndermek akışı bozar ve dönüş
yolu bizden geçmediği için düzeltilemez. Bu kısıt iki yerde kendini gösteriyor:

- `-s` (Host'tan sonraki boşluğu sil) ve `-a` (metod ile URI arasına boşluk ekle)
  **her zaman birlikte** uygulanır — biri bir bayt alır, diğeri bir bayt verir.
- TLS kayıt bölme ikinci kayıt için 5 bayt fazladan başlık ister. Bu 5 bayt
  ClientHello'nun **içinden** geri kazanılır: padding eklentisi (RFC 7685)
  küçültülerek ya da bir GREASE eklentisi (RFC 8701) atılarak. İkisi de
  sunucunun yok saymak zorunda olduğu alanlar. Geri kazanılacak bayt yoksa
  dpiOS bölmeyi yapmaz — paketi asla büyütmez.

Paketler `/dev/bpf` üzerinden ham ethernet çerçevesi olarak gönderiliyor. Bu yol
routing tablosunu ve pf çıkış zincirini atlıyor, dolayısıyla kendi paketlerimiz
tekrar utun'a düşüp sonsuz döngüye girmiyor.

---

## Kurulum

Gereksinim: macOS 11+, Xcode Command Line Tools (`xcode-select --install`).

### Tek komut

```bash
sudo ./install.sh
```

Sırasıyla: derler → makineyi doğrular → engelin türünü teşhis eder (DNS mi,
DPI mi) → hangi preset'in işe yaradığını **deneyerek** bulur → servisi kurar →
sonucu raporlar.

DNS engeli tespit ederse `profiles/dpios-encrypted-dns.mobileconfig` profilini
açar; **Sistem Ayarları → Genel → Aygıt Yönetimi**'nden onaylaman yeterli.

Kendi site listeni de verebilirsin:

```bash
sudo ./install.sh discord.com baskasite.com
```

### Elle, adım adım

<details>
<summary>install.sh'ın yaptıklarını kendin yapmak istersen</summary>

**1. Derle**

```bash
make
make test          # protokol ayrıştırıcılarının birim testleri
```

**2. Kurmadan önce makineni doğrula**

```bash
sudo ./build/dpios --check
```

Root yetkisini, varsayılan rotayı, gateway MAC adresini, utun oluşturmayı, pf
anchor'ının erişilebilirliğini, `route-to` kuralının kabul edilip edilmediğini
ve BPF enjeksiyonunu tek tek dener, sonra hepsini temizler. Sisteminde kalıcı
hiçbir şey bırakmaz.

**3. Dene**

```bash
sudo ./build/dpios -5 -vv
```

Başka bir terminalde bir siteye gir. `TLS ClientHello -> site.com` satırlarını
görüyorsan motor çalışıyor. Durdurmak için `Ctrl-C`.

**4. Memnunsan kur**

```bash
sudo make install          # /usr/local/bin/dpios
```

</details>

---

## Kullanım

```bash
sudo dpios -5                          # önerilen başlangıç
sudo dpios -6                          # -5 yetmezse
sudo dpios -9 --frag-sni               # en agresif
sudo dpios -5 --blacklist hosts.txt    # sadece listedeki alan adlarına uygula
sudo dpios -5 -vv                      # paket paket log
```

Henüz `make install` yapmadıysan `dpios` yerine `./build/dpios` yaz.
Durdurmak için `Ctrl-C`; çalışırken `Ctrl-T` (SIGINFO) canlı istatistik basar.

### Canlı panel

Terminalde çalıştırdığında log seli yerine yerinde güncellenen bir panel çizer:

```
╭─ dpiOS 0.1.0 ─────────────────────────────────────────── preset -5 ╮
│ en0 → utun5    ports 80,443    decoys on, auto-ttl                 │
╰────────────────────────────────────────────────────────────────────╯

  uptime 00:04:12   injected 1,284   errors 0

  TLS        142  ████████████████████████████████████████
  HTTP        18  █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  decoys 142   fragments 320   untouched 968

  recent
    23:47:34  TLS   static.cloudflareinsights.com   split @ 2
    23:47:34  HTTP  cdn.example.net                 split @ 2
    23:47:34  TLS   www.example.com                 split @ 2

  Ctrl-C to stop
```

Hata ve uyarı satırları panelin üstünde birikir, panel altta kalır — hiçbir log
kaybolmaz. Panel `-v`/`-vv`, `--syslog` ve çıktı bir dosyaya/pipe'a gittiğinde
(launchd dahil) kendiliğinden kapanır. Zorla kapatmak için `--no-ui`.

### Preset'ler

GoodbyeDPI ile aynı numaralandırma. TLS kayıt bölme hepsinde varsayılan olarak
açık.

| Preset | Ne yapar |
|--------|----------|
| `-1`…`-4` | HTTP odaklı: `Host:` header hileleri + hafif parçalama |
| `-5` | ClientHello 2. bayttan bölünür, ters sırada, otomatik TTL'li sahte paket |
| `-6` | `-5` gibi ama sahte paket bozuk sequence numarasıyla |
| `-7` | `-5` gibi ama sahte paket bozuk checksum'la |
| `-8` | `-6` + `-7` birlikte |
| `-9` | `-8` + bölme noktası hostname'in tam ortasında |

`install.sh` bunları senin ağında deneyip çalışanı seçiyor; elle seçeceksen
`-5` ile başla.

### Öne çıkan bayraklar

```
      --record-frag      ClientHello'yu iki TLS kaydına böl (varsayılan açık)
      --no-record-frag   kapat
-e, --frag-https N       TLS ClientHello'yu N. bayttan böl (varsayılan 2)
-f, --frag-http N        HTTP isteğini N. bayttan böl
      --frag-sni         bölmeyi hostname'in ortasında yap
      --reverse-frag     ikinci parçayı önce gönder
      --fake             gerçek isteğin önüne sahte istek koy
      --auto-ttl=1-3-10  sahte paketin TTL'ini hop sayısından hesapla
      --wrong-seq        sahte paketi pencere dışı sequence ile gönder
      --wrong-chksum     sahte paketin TCP checksum'ını boz
      --port 8080        ek hedef port (tekrarlanabilir)
      --blacklist FILE   sadece bu alan adlarına dokun
      --whitelist FILE   bu alan adlarına asla dokunma
      --inject bpf|raw   enjeksiyon yöntemi
      --dry-run          tespit et ve logla, ama hiçbir şeyi değiştirme
      --check            makineyi doğrula ve çık
      --unload           artık kalmış pf kurallarını temizle ve çık
```

Tam liste: `dpios --help`.

### Liste dosyası formatı

Satır başına bir alan adı. `#` ile yorum, `0.0.0.0 host` (hosts dosyası) biçimi
ve baştaki `*.` / `.` kabul edilir. Eşleşme alt alan adlarını kapsar:
`example.com` girdisi `www.example.com`'u da yakalar, `notexample.com`'u
yakalamaz.

```
# örnek
example.com
*.cdn.example.net
```

---

## Servis olarak çalıştırma

`install.sh` bunu zaten yapıyor. Elle yönetmek istersen:

```bash
sudo ./scripts/install-service.sh -5              # kur (preset seçerek)
tail -f /var/log/dpios.log                        # loglar
sudo launchctl print system/com.dpios.daemon      # durum
sudo ./scripts/uninstall-service.sh               # kaldır
sudo ./scripts/uninstall-service.sh --purge       # binary + log dahil sil
```

`install-service.sh` önce `--check` çalıştırır, başarısız olursa kurulumu
yapmaz.

---

## Sorun giderme

### Acil: ağım gitti

dpiOS temizlenmeden ölürse (kill -9, panic) pf'te artık var olmayan bir utun'a
işaret eden kural kalır ve web trafiği kaybolur. Geri almak için:

```bash
sudo pfctl -a com.apple/dpios -F all
```

Normal kapanışlarda (Ctrl-C, SIGTERM, hatta SIGSEGV) bu otomatik yapılır.

### Tablo

| Belirti | Bakılacak yer |
|---------|---------------|
| `--check`: "anchor com.apple/* missing" | `sudo pfctl -f /etc/pf.conf` |
| `--check`: "gateway hwaddr" hatası | Router'a `ping` atıp tekrar dene |
| `--check`: "packet injection" hatası | `--inject raw` dene |
| Hiçbir şey değişmiyor gibi | `sudo dpios -5 -vv` — `TLS ClientHello -> site.com` satırı görüyor musun? |
| Motor trafiği görüyor ama site açılmıyor | Muhtemelen DNS katmanı. `install.sh` teşhis eder |
| Site açılmıyor, DNS de temiz | Farklı preset (`-6`, `-7`, `-9`) veya `--frag-sni` |
| VPN açıkken çalışmıyor | Beklenen: varsayılan rota utun üzerindeyse `--inject raw` gerekir |

Gerçekten ne gönderildiğini görmek için:

```bash
sudo tcpdump -i en0 -n 'tcp port 443 and host <hedef-ip>'
```

Bir ClientHello için iki ayrı segment (ve `--fake` açıksa fazladan bir paket)
görmelisin.

---

## Sınırlar

GoodbyeDPI'ın bazı özellikleri bu mimariyle karşılanamıyor. Gizlemek yerine
açıkça yazıyorum:

- **`-p` / passive DPI engelleme.** Gelen paketler dpiOS'a hiç uğramıyor,
  dolayısıyla DPI'ın gönderdiği sahte RST'yi düşüremeyiz. Bayrak kabul ediliyor
  ama uyarı basıp yok sayılıyor.
- **DNS engelleme.** dpiOS TLS el sıkışmasına müdahale eder, DNS sorgusuna
  değil. DNS katmanı için depodaki şifreli DNS profili kullanılıyor.
- **`-n` / ilk segment ACK'ini bekleme.** Kernel'in TCP durum makinesini
  userspace'ten yönetmiyoruz.
- **TLS kayıt bölme her ClientHello'da yapılamaz.** Geri kazanılacak 5 bayt
  (padding ya da GREASE eklentisi) yoksa dpiOS bölmeyi atlar. Chromium tabanlı
  istemciler GREASE gönderdiği için orada güvenilir çalışır.
- **IPv6** deneysel (`--ipv6`, varsayılan kapalı).

---

## Geliştirme

### Proje yapısı

```
install.sh      tek komutluk kurulum + teşhis
profiles/       şifreli DNS (DoH) yapılandırma profili
src/
  main.c        kqueue döngüsü, sinyaller, kurulum/temizlik sırası
  cli.c         argüman ayrıştırma
  config.c      varsayılanlar ve preset'ler
  check.c       --check self-test
  ui.c          canlı terminal paneli
  utun.c        utun cihazı oluşturma (PF_SYSTEM kernel control)
  pf.c          pf anchor'ına route-to kurallarını yükleme/temizleme
  inject.c      BPF ve raw socket enjektörleri
  netinfo.c     varsayılan rota, arayüz, ARP/NDP tablosu (sysctl PF_ROUTE)
  monitor.c     pasif TTL gözlemcisi (--auto-ttl için)
  engine.c      asıl DPI bypass mantığı
  tls.c         ClientHello ayrıştırma, TLS kayıt bölme, sahte hello üretimi
  http.c        HTTP header ayrıştırma ve manipülasyonu
  blacklist.c   alan adı listeleri
  checksum.c    IPv4/IPv6/TCP/UDP checksum
  util.c        fork/exec yardımcıları
tests/          birim testleri
```

### Testler

```bash
make test
```

Taşınabilir yarıyı gerçekten çalıştırarak test eder: TLS/HTTP ayrıştırıcıları,
TLS kayıt bölme, sahte ClientHello üreteci, checksum kodu, alan adı listeleri,
preset'ler. En kritik iki invaryant burada doğrulanıyor:

- `dp_http_mangle` paket uzunluğunu değiştirmiyor
- `dp_tls_split_records` ya uzunluğu birebir koruyor ya da hiç dokunmuyor

### Linux'tan macOS'a derleme

Xcode olmayan bir makinede geliştiriyorsan:

```bash
./scripts/crossbuild.sh            # arm64
./scripts/crossbuild.sh x86_64     # intel
```

Zig'in C derleyicisi Apple'ın libSystem stub'larını ve Darwin header'larının
çoğunu içeriyor, dolayısıyla `zig cc -target aarch64-macos` gerçek bir Mach-O
binary üretiyor. Zig'de bulunmayan dört header (`net/if_utun.h`, `net/bpf.h`,
`sys/sys_domain.h`, `netinet/ip6.h`) Apple'ın açık kaynak XNU deposundan
çekiliyor — yani derleme gerçek tanımlara karşı yapılıyor.

Bu bir geliştirme aracı; ürettiği binary imzasız ve gerçek donanımda test
edilmemiş olur. Mac'te doğrudan `make` kullan.

---

## Lisans ve sorumluluk

Bu araç, ağ trafiğinizin nasıl şekillendirildiğini kendi makinenizde kontrol
etmeniz içindir. Kullandığınız ağın kurallarına uymak sizin sorumluluğunuzdadır.
