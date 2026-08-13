# dpiOS

GoodbyeDPI'ın macOS (Apple Silicon) karşılığı. DPI (Deep Packet Inspection)
tabanlı erişim engellemelerini, giden TCP paketlerini parçalayarak, sahte
paketler enjekte ederek ve HTTP başlıklarını değiştirerek aşar.

- **Kernel extension gerektirmez.** Apple Silicon'da kext yolu pratikte kapalı;
  dpiOS bunun yerine `pf` + `utun` + `/dev/bpf` üçlüsünü kullanıyor.
- **Apple Developer hesabı gerektirmez.** Network Extension'a, imzaya,
  entitlement'a ihtiyaç yok. Sadece `sudo` ister.
- **GoodbyeDPI ile aynı preset numaraları** (`-1`…`-9`), aynı bayrak isimleri.
- Tek bir C binary'si, harici bağımlılık yok. `launchd` servisi olarak
  kurulabilir.

Hızlı başlangıç:

```bash
make && sudo ./build/dpios --check && sudo ./build/dpios -5
```

---

## Nasıl çalışıyor?

GoodbyeDPI Windows'ta WinDivert sürücüsüyle paketleri çekirdek seviyesinde
yakalar. macOS'ta WinDivert yok ve Apple Silicon'da kext yolu pratikte kapalı.
dpiOS bunun yerine macOS'un kendi parçalarını birleştirir:

```
  uygulama (Safari, curl…)
        │
        ▼
  kernel TCP/IP yığını          ← kaynak IP burada seçilir: 192.168.1.x
        │
        ▼
  pf: "route-to (utunN)"        ← sadece TCP 80/443, sadece internete giden
        │
        ▼
  utun cihazı  ──────────────▶  dpios (userspace)
                                   │  ClientHello'yu ikiye böl
                                   │  sahte paket üret (düşük TTL / bozuk checksum)
                                   │  HTTP header'larını değiştir
                                   ▼
                                /dev/bpf ──▶ en0 ──▶ internet

  dönüş trafiği: en0 ──▶ kernel   (dpios'a hiç uğramaz)
```

Kritik iki tasarım kararı:

1. **`pf route-to`** ile sadece ilgilendiğimiz trafiği utun'a çeviriyoruz.
   Varsayılan rotayı değiştirmediğimiz için kaynak IP adresi değişmiyor —
   dolayısıyla NAT yazmaya gerek yok.
2. **Dönüş trafiği bize uğramıyor.** Kernel soketi zaten 4'lü demeti tanıyor.
   Bu, throughput için çok iyi; karşılığında gelen paketleri filtreleyemiyoruz
   (aşağıdaki "Yapılamayanlar" bölümüne bakın).

Paketler `/dev/bpf` üzerinden ham ethernet çerçevesi olarak gönderiliyor. Bu
yol routing tablosunu ve pf çıkış zincirini tamamen atlıyor, dolayısıyla
kendi paketlerimiz tekrar utun'a düşüp sonsuz döngüye girmiyor.

---

## Kurulum

Gereksinim: macOS 11+, Xcode Command Line Tools (`xcode-select --install`).

### 1. Derle

```bash
git clone https://github.com/ahmethasmerdogan/dpiOS.git
cd dpiOS
make
make test          # protokol ayrıştırıcılarının birim testleri
```

### 2. Kurmadan önce makineni doğrula

```bash
sudo ./build/dpios --check
```

Bu komut root yetkisini, varsayılan rotayı, gateway MAC adresini, utun
oluşturmayı, pf anchor'ının erişilebilirliğini, `route-to` kuralının kabul
edilip edilmediğini ve BPF enjeksiyonunu tek tek dener; sonra hepsini
temizler. Sisteminde kalıcı hiçbir şey bırakmaz.

Hepsi yeşilse devam. Kırmızı bir satır varsa aşağıdaki
[sorun giderme](#sorun-giderme) tablosuna bak.

### 3. Dene

```bash
sudo ./build/dpios -5 -vv
```

Başka bir terminalde bir siteye gir. `TLS ClientHello -> site.com` satırlarını
görüyorsan motor çalışıyor demektir. Durdurmak için `Ctrl-C`.

### 4. Memnunsan kur

```bash
sudo make install          # /usr/local/bin/dpios
```

Bundan sonra her yerden `sudo dpios ...` diyebilirsin. Boot'ta otomatik
başlaması için [servis bölümüne](#servis-olarak-çalıştırma-launchd) bak.

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

Durdurmak için `Ctrl-C`. Çalışırken `Ctrl-T` (SIGINFO) canlı istatistik basar.

### Preset'ler

GoodbyeDPI ile aynı numaralandırma:

| Preset | Ne yapar |
|--------|----------|
| `-1`…`-4` | HTTP odaklı: `Host:` header hileleri + hafif parçalama |
| `-5` | ClientHello 2. byte'tan bölünür, ters sırada, otomatik TTL'li sahte paket |
| `-6` | `-5` gibi ama sahte paket bozuk sequence numarasıyla |
| `-7` | `-5` gibi ama sahte paket bozuk checksum'la |
| `-8` | `-6` + `-7` birlikte |
| `-9` | `-8` + bölme noktası hostname'in tam ortasında |

Türkiye'deki tipik DPI kutuları için **`-5` ile başlayın**, çalışmazsa `-6`,
sonra `-9` deneyin.

### Öne çıkan bayraklar

```
-e, --frag-https N     TLS ClientHello'yu N. byte'tan böl (varsayılan 2)
-f, --frag-http N      HTTP isteğini N. byte'tan böl
    --frag-sni         bölmeyi hostname'in ortasında yap (en etkilisi)
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
```

Tam liste: `dpios --help`.

### Blacklist formatı

Satır başına bir alan adı. `#` ile yorum, `0.0.0.0 host` (hosts dosyası)
biçimi ve baştaki `*.` / `.` de kabul edilir. Eşleşme alt alan adlarını
kapsar: `example.com` girdisi `www.example.com`'u da yakalar.

```
# örnek
example.com
*.cdn.example.net
```

---

## Servis olarak çalıştırma (launchd)

```bash
sudo ./scripts/install-service.sh          # -5 ile
sudo ./scripts/install-service.sh -6 --frag-sni
```

Script önce `--check` çalıştırır, başarısız olursa kurulumu yapmaz.

```bash
tail -f /var/log/dpios.log                       # loglar
sudo launchctl print system/com.dpios.daemon     # durum
sudo ./scripts/uninstall-service.sh              # kaldır
sudo ./scripts/uninstall-service.sh --purge      # binary + log dahil sil
```

---

## Bir şeyler ters giderse

**En önemli komut bu.** dpiOS temizlenmeden ölürse (kill -9, panic), pf'te
artık var olmayan bir utun'a işaret eden bir kural kalır ve tüm web trafiğiniz
kaybolur. Geri almak için:

```bash
sudo pfctl -a com.apple/dpios -F all
```

veya:

```bash
sudo dpios --unload
```

Normal kapanışlarda (Ctrl-C, SIGTERM, hatta SIGSEGV) bu otomatik yapılır.

### Sorun giderme

| Belirti | Bakılacak yer |
|---------|---------------|
| `--check`'te "anchor com.apple/* missing" | `sudo pfctl -f /etc/pf.conf` |
| `--check`'te "gateway hwaddr" hatası | Router'a bir `ping` atıp tekrar deneyin |
| `--check`'te "packet injection" hatası | `--inject raw` deneyin |
| Hiçbir şey değişmiyor gibi | `sudo dpios -5 -vv` ile paket log'una bakın; `TLS ClientHello -> site.com` satırı görüyor musunuz? |
| Görüyor ama site açılmıyor | Farklı preset (`-6`, `-7`, `-9`) veya `--frag-sni` |
| VPN açıkken çalışmıyor | Beklenen: varsayılan rota utun üzerindeyse `--inject raw` gerekir |

Gerçekten ne gönderildiğini görmek için:

```bash
sudo tcpdump -i en0 -n 'tcp port 443 and host <hedef-ip>'
```

Bir ClientHello için iki ayrı segment (ve `--fake` açıksa fazladan bir paket)
görmelisiniz.

---

## Yapılamayanlar (ve nedenleri)

GoodbyeDPI'ın bazı özellikleri macOS'ta bu mimariyle karşılanamıyor. Bunları
gizlemek yerine açıkça yazıyorum:

- **`-p` / passive DPI engelleme.** Gelen paketler dpiOS'a hiç uğramıyor,
  dolayısıyla DPI'ın gönderdiği sahte RST veya redirect paketini düşüremiyoruz.
  Bayrak kabul ediliyor ama uyarı basıp yok sayılıyor.
- **DNS yönlendirme (`--dns-addr`).** Kapsam dışı; bunun için macOS'ta zaten
  daha iyi araçlar var (`networksetup -setdnsservers`, dnscrypt-proxy).
- **`-n` / ilk segment ACK'ini bekleme.** Kernel'in TCP durum makinesini
  userspace'ten yönetmiyoruz.
- **IPv6** deneysel (`--ipv6`). `route-to` IPv6 tarafında daha az test edilmiş
  bir yol; sorun görürseniz kapalı bırakın (varsayılan kapalı).

Ayrıca bir tasarım kısıtı: **paket uzunluğu asla değişmiyor.** Kernel'in TCP
yığını o sequence numarasında tam olarak N byte gönderdiğini varsayıyor; bir
byte eksik/fazla göndermek akışı bozar. Bu yüzden `-s` (Host'tan sonraki
boşluğu sil) ve `-a` (metod ile URI arasına boşluk ekle) her zaman birlikte
uygulanır — biri bir byte alır, diğeri bir byte verir.

---

## Proje yapısı

```
src/
  main.c        kqueue döngüsü, sinyaller, kurulum/temizlik sırası
  cli.c         argüman ayrıştırma
  config.c      varsayılanlar ve preset'ler
  check.c       --check self-test
  utun.c        utun cihazı oluşturma (PF_SYSTEM kernel control)
  pf.c          pf anchor'ına route-to kurallarını yükleme/temizleme
  inject.c      BPF ve raw socket enjektörleri
  netinfo.c     varsayılan rota, arayüz, ARP/NDP tablosu (sysctl PF_ROUTE)
  monitor.c     pasif TTL gözlemcisi (--auto-ttl için)
  engine.c      asıl DPI bypass mantığı
  tls.c         ClientHello / SNI ayrıştırma, sahte ClientHello üretimi
  http.c        HTTP header ayrıştırma ve manipülasyonu
  blacklist.c   alan adı listeleri
  checksum.c    IPv4/IPv6/TCP/UDP checksum
  util.c        fork/exec yardımcıları
```

---

## Geliştirme

### Testler

```bash
make test
```

Taşınabilir yarıyı — TLS/HTTP ayrıştırıcıları, sahte ClientHello üreticisi,
checksum kodu, alan adı listeleri ve preset'ler — gerçekten çalıştırarak test
eder. En kritik invaryant burada doğrulanıyor: **`dp_http_mangle` paket
uzunluğunu asla değiştirmiyor.**

### Linux'tan macOS'a derleme

Xcode olmayan bir makinede geliştiriyorsanız:

```bash
./scripts/crossbuild.sh            # arm64
./scripts/crossbuild.sh x86_64     # intel
```

Zig'in C derleyicisi Apple'ın libSystem stub'larını ve Darwin header'larının
çoğunu içeriyor, dolayısıyla `zig cc -target aarch64-macos` gerçek bir Mach-O
binary üretiyor. Zig'de bulunmayan dört header (`net/if_utun.h`, `net/bpf.h`,
`sys/sys_domain.h`, `netinet/ip6.h`) Apple'ın kendi açık kaynak XNU deposundan
çekiliyor — yani derleme gerçek tanımlara karşı yapılıyor, uydurma stub'lara
karşı değil.

Bu bir geliştirme aracı: derleme hatalarını Mac'e gitmeden yakalamak için.
Ürettiği binary imzasız ve gerçek donanımda test edilmemiş olur. Mac'te
doğrudan `make` kullanın.

---

## Lisans ve sorumluluk

Bu araç, ağ trafiğinizin nasıl şekillendirildiğini kendi makinenizde kontrol
etmeniz içindir. Kullandığınız ağın kurallarına uymak sizin sorumluluğunuzdadır.
