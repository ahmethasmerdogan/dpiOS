# dpiOS

macOS için DPI aşma aracı. Windows'taki GoodbyeDPI'ın yaptığı işi Apple
Silicon'da yapıyor: giden bağlantıları, araya giren filtrenin ne istediğini
anlayamayacağı şekilde yeniden biçimlendiriyor.

Kernel extension yok, Apple Developer hesabı yok, harici bağımlılık yok. Tek
bir C programı ve `sudo`.

```bash
cd ~ && git clone https://github.com/ahmethasmerdogan/dpiOS.git 2>/dev/null; \
cd ~/dpiOS && git pull && sudo bash install.sh
```

Zaten indirdiysen de aynı komut çalışır; günceller ve devam eder.

---

## Ne yapıyor

Türkiye'de bir siteye erişemiyorsan, genelde iki ayrı engel vardır ve ikisi de
ayrı ayrı çözülmek zorundadır.

**Birincisi DNS.** Adres sorduğunda sana sitenin gerçek adresi yerine engel
sayfasının adresi dönüyor. "DNS'i 8.8.8.8 yap" tavsiyesi buna çare değil, çünkü
sorgunun kendisi yolda değiştiriliyor — hangi sunucuya sorduğunun bir önemi yok.
dpiOS bunu, sorguyu HTTPS'in içine saklayarak çözüyor.

**İkincisi DPI.** Adresi doğru bulsan bile, bağlantıyı kurarken hangi siteye
gittiğini söyleyen kısım (SNI) açıkta gidiyor; filtre onu görüp bağlantıyı
kesiyor. dpiOS bu kısmı, filtrenin okuyamayacağı ama sunucunun sorunsuz
anlayacağı şekilde parçalara bölüyor.

Kurulum ikisini de test edip hangisinin gerektiğine kendi karar veriyor.

---

## Kurulum

macOS 11 veya üstü ve Xcode Command Line Tools gerekiyor. Yoksa script zaten
kurman gerektiğini söyleyecek (`xcode-select --install`).

```bash
sudo bash install.sh
```

Yaptıkları sırayla:

1. Derler.
2. Makinede gerekli her şeyin çalıştığını doğrular (`--check`).
3. Engelin DNS mi DPI mi olduğunu ölçer.
4. Hangi ayarın işe yaradığını **deneyerek** bulur — tahmin etmez.
5. Bulduğu ayarla servisi kurar, açılışta otomatik başlasın diye.
6. Sonucu söyler.

Ekranda şuna benzer bir şey görürsün — her adım kendi sırasında, uzun sürenlerin
yanında dönen bir gösterge:

```
╭────────────────────────────────────────────────────────────────────╮
│ dpiOS  ·  DPI aşma aracı                                           │
│ macOS 15.5 · arm64 · kayıt: /tmp/dpios-install.log                 │
╰────────────────────────────────────────────────────────────────────╯

[1/6] Derleniyor
    ✓ build/dpios hazır (028c4c5)

[2/6] Makine doğrulanıyor
    ✓ egress arayüzü en0
    ✓ pf route-to kuralları kabul edildi

[3/6] Engelin türü tespit ediliyor
    ✗ discord.com — sistem 195.175.254.2 diyor, gerçek adresler arasında yok

[4/6] Şifreli DNS deneniyor
    ✓ şifreli DNS çalışıyor — alt alan adları da kapsanıyor

[5/6] Hangi ayar işe yarıyor, deneniyor
    ████████████░░░░░░░░░░  preset -6 deneniyor
```

Varsayılan olarak `discord.com`'u test eder. Başka siteler için:

```bash
sudo bash install.sh discord.com baskasite.com
```

Ne olup bittiğinin tamamı `/tmp/dpios-install.log` dosyasına yazılır. Bir yerde
takılırsan paylaşman gereken tek şey o dosya.

### Kaldırmak

```bash
sudo bash scripts/uninstall-service.sh
```

Servisi durdurur, pf kurallarını temizler, `/etc/hosts`'a eklenenleri siler,
kapatılmışsa IPv6'yı geri açar. `--purge` eklersen binary ve log da gider.

---

## Çalışmıyorsa

Önce şu: **ağın tamamen gittiyse** panik yapma, tek komut geri getirir.

```bash
sudo pfctl -a com.apple/dpios -F all
```

Normalde dpiOS kapanırken bunu kendisi yapıyor — Ctrl-C, kill, hatta çökme
durumunda bile. Bu komut sadece o da olmazsa diye duruyor.

Sonrası:

| Ne oluyor | Ne yap |
|---|---|
| `command not found` | `dpiOS` klasöründe değilsin ya da `git pull` yapmadın. En üstteki komut ikisini de halleder |
| Site hâlâ açılmıyor | `sudo dpios -6`, sonra `-7`, sonra `-9` dene |
| Uygulama açılmıyor ama web sürümü açılıyor | Uygulamayı ⌘Q ile tamamen kapat, öyle aç. Pencereyi kapatmak yetmez |
| Tarayıcı bazen açıyor bazen açmıyor | `sudo dpios -5 --block-quic` — bazı siteler UDP'ye kaçıyor |
| Hiçbir şey değişmemiş gibi | `sudo dpios -5 -vv` çalıştır; `TLS ClientHello -> site.com` satırı görüyor musun |
| VPN açıkken bozuluyor | `--inject raw` ekle |

Gerçekten ne gönderildiğini görmek istersen:

```bash
sudo tcpdump -i en0 -n 'tcp port 443 and host <hedef-ip>'
```

Tek bir bağlantı için iki ayrı paket görmen lazım.

---

## Neler çalışır

Ölçtüklerim:

- **Web siteleri** — çalışıyor, hem tarayıcıda hem `curl` ile doğrulandı.
- **Masaüstü uygulamaları** — çalışıyor. Bunlar `gateway.us-east1-b.discord.gg`
  gibi, çalışırken öğrendikleri adresleri çözüyor; bu yüzden `/etc/hosts`'a elle
  adres yazmak yetmiyor, gerçek bir DNS çözümleyici gerekiyor. dpiOS onu içinde
  barındırıyor.
- **Sesli sohbet** — engellenmiş görünmüyor. Discord'un ses sunucuları
  `discord.media` altında ve bu alan adı ne DNS'te ne de DPI'da engelli çıktı
  (`latency.discord.media` hem doğru adresi veriyor hem de bağlantı sorunsuz
  kuruluyor).

Çalışmayanlar ve nedenleri:

- **Gelen paketleri filtreleme (`-p`).** GoodbyeDPI'ın bu özelliği burada
  yapılamıyor: dönüş trafiği tasarım gereği dpiOS'a uğramıyor, dolayısıyla
  filtrenin gönderdiği sahte RST paketi yakalanamıyor. Bayrağı verirsen uyarı
  basıp yok sayar.
- **QUIC / HTTP/3.** UDP üzerinden gittiği için TCP'yi işleyen dpiOS'a hiç
  uğramıyor. `--block-quic` ile UDP/443'ü kapatıp tarayıcıyı TCP'ye
  düşürebilirsin, ama bu QUIC'i sorunsuz kullanan siteleri de yavaşlatır. O
  yüzden varsayılan olarak kapalı.
- **Bazı ClientHello'lar.** Aşağıda anlatılan 5 baytı bulamazsa dpiOS o
  bağlantıya dokunmuyor. Paketi asla büyütmüyor.
- **IPv6** deneysel (`--ipv6`), varsayılan kapalı.

---

## Ayarlar

Preset numaraları GoodbyeDPI ile aynı, alışkanlık bozulmasın diye.

| | Ne yapar |
|---|---|
| `-1`…`-4` | HTTP odaklı, hafif. Eski usul engellere |
| `-5` | Önerilen başlangıç. TLS kayıt bölme + parçalama + otomatik TTL'li sahte paket |
| `-6` | Sahte paket bozuk sequence numarasıyla gider |
| `-7` | Sahte paket bozuk checksum'la gider |
| `-8` | `-6` ve `-7` birlikte |
| `-9` | `-8` + bölme noktası tam alan adının ortasında |

`install.sh` bunları senin bağlantında deneyip çalışanı seçtiği için normalde
elle uğraşman gerekmiyor.

Sık kullanılan bayraklar:

```
--doh              şifreli DNS çözümleyiciyi çalıştır (127.0.0.1:53)
--record-frag      ClientHello'yu iki TLS kaydına böl (varsayılan açık)
--frag-sni         bölmeyi alan adının tam ortasında yap
--block-quic       UDP/443'ü kapat, tarayıcı TCP'ye düşsün
--blacklist FILE   sadece listedeki alan adlarına dokun
--whitelist FILE   listedekilere hiç dokunma
--dry-run          tespit et ve logla ama hiçbir şeyi değiştirme
--check            makineyi doğrula ve çık
--unload           kalmış pf kurallarını temizle ve çık
-vv                paket paket log
```

Tamamı için `dpios --help`.

Liste dosyalarında satır başına bir alan adı yazılır; `#` yorum, `0.0.0.0 host`
biçimi ve baştaki `*.` kabul edilir. `example.com` yazmak `www.example.com`'u da
kapsar, `notexample.com`'u kapsamaz.

Terminalde çalıştırdığında log seli yerine canlı bir panel çizer: kaç paket
işlendi, hangi alan adları geçti, kaç hata oldu. `-vv` verirsen ya da servis
olarak çalışırsa düz log'a döner.

---

## Nasıl çalışıyor

GoodbyeDPI, Windows'ta WinDivert sürücüsüyle paketleri çekirdek seviyesinde
yakalar. macOS'ta öyle bir sürücü yok ve Apple Silicon'da kext yazma yolu
pratikte kapalı. dpiOS aynı işi macOS'un kendi parçalarını birleştirerek
yapıyor:

```
  uygulama
     │
     ▼
  kernel TCP/IP            ← kaynak IP burada seçilir
     │
     ▼
  pf: route-to utunN       ← sadece TCP 80/443, sadece internete çıkan
     │
     ▼
  utun ──────────────▶  dpios
                          │  ClientHello'yu iki TLS kaydına böl
                          │  TCP segmentine böl, sırayı ters çevir
                          │  sahte paket üret
                          ▼
                       /dev/bpf ──▶ en0 ──▶ internet

  dönüş trafiği: en0 ──▶ kernel   (dpios'a uğramaz)
```

Üç karar bu mimariyi belirliyor.

**Varsayılan rota değişmiyor.** `pf route-to` sadece ilgilendiğimiz trafiği
utun'a çeviriyor. Kaynak adres değişmediği için NAT yazmaya gerek kalmıyor.

**Dönüş trafiği bize uğramıyor.** Kernel bağlantıyı zaten tanıyor. Hız için
iyi; bedeli, gelen paketlere müdahale edememek.

**Paket uzunluğu asla değişmiyor.** Kernel o sequence numarasında tam N bayt
gönderdiğini sanıyor. Bir bayt eksik ya da fazla göndermek akışı bozar ve dönüş
yolu bizden geçmediği için düzeltilemez. Bu kısıt kendini iki yerde gösteriyor:

- `-s` (Host'tan sonraki boşluğu sil) ve `-a` (metod ile URI arasına boşluk ekle)
  hep birlikte uygulanıyor. Biri bir bayt alıyor, öbürü bir bayt veriyor.
- TLS kayıt bölme, ikinci kayıt için 5 bayt fazladan başlık istiyor. O 5 bayt
  ClientHello'nun içinden geri kazanılıyor: padding eklentisi (RFC 7685)
  küçültülüyor ya da bir GREASE eklentisi (RFC 8701) atılıyor. İkisi de
  sunucunun yok saymak zorunda olduğu alanlar. Bulunamazsa dpiOS o bağlantıyı
  olduğu gibi bırakıyor.

Paketler `/dev/bpf` üzerinden ham ethernet çerçevesi olarak gönderiliyor. Bu yol
routing tablosunu ve pf çıkışını atladığı için kendi ürettiğimiz paketler tekrar
utun'a düşüp döngüye girmiyor.

---

## Ölçümler

Buradaki her şey bir Türk ISS'i üzerinde ölçüldü.

**DNS tarafı.** Sistem `discord.com` için `195.175.254.2` diyor, gerçeği
`162.159.136.232`. Sorgu, hangi sunucuya gönderilirse gönderilsin araya
giriliyor:

| | `example.com` | `discord.com` |
|---|---|---|
| `1.1.1.1` UDP | cevap geliyor | zaman aşımı |
| `1.1.1.1` TCP | cevap geliyor | RST |
| DoH (şifreli) | cevap geliyor | gerçek adres |

Filtre alan adına duyarlı ama harfe duyarsız — büyük/küçük karıştırmak işe
yaramadı. Ayrıca wildcard: `rastgele-isim.discord.gg` gibi hiç var olmayan bir
isim bile engel sayfasına gidiyor. Statik bir `/etc/hosts` listesinin
uygulamaları kurtaramamasının sebebi bu.

**DPI tarafı.** Adres doğru olsa bile TLS el sıkışması 14 ms'de RST yiyor.
Denenenler:

| | Sonuç |
|---|---|
| dokunulmamış (kontrol) | RST |
| TCP'de 2. bayttan bölme | RST |
| TCP'de alan adının ortasından bölme | RST |
| alan adını karışık harfle yazma | RST |
| SNI eklentisini listenin sonuna alma | RST |
| **iki TLS kaydına bölme** | **ServerHello** |

Yani bu filtre TCP akışını birleştirdikten sonra inceliyor; segment bölmek işe
yaramıyor. Kayıt katmanında bölmek yarıyor, çünkü bir handshake mesajının birden
çok kayda yayılması TLS'te geçerli ve sadece ilk kaydı ayrıştıran bir
denetleyici bütün mesajı hiç görmüyor.

Bu, dpiOS'un ürettiği baytlarla canlı olarak doğrulandı. Üç ClientHello
biçiminin üçünde de işlenmemiş paket RST alıyor, işlenmiş paket ServerHello
alıyor: tek segmente sığan hello, Chromium'unki gibi iki segmente taşan hello,
ve padding eklentisi segmenti aşan hello. Üçünde de uzunluk birebir korunuyor.

---

## Geliştirme

```
install.sh      tek komutluk kurulum ve teşhis
src/
  main.c        kqueue döngüsü, sinyaller, kurulum/temizlik sırası
  cli.c         argümanlar
  config.c      varsayılanlar ve preset'ler
  check.c       --check
  ui.c          canlı terminal paneli
  dns.c         şifreli DNS çözümleyici
  utun.c        utun cihazı (PF_SYSTEM kernel control)
  pf.c          pf kurallarını yükleme ve temizleme
  inject.c      BPF ve raw socket enjektörleri
  netinfo.c     rota, arayüz, ARP/NDP tablosu
  monitor.c     pasif TTL gözlemcisi
  engine.c      DPI bypass mantığı
  tls.c         ClientHello ayrıştırma ve TLS kayıt bölme
  http.c        HTTP header işleme
  blacklist.c   alan adı listeleri
  checksum.c    IPv4/IPv6/TCP/UDP checksum
  util.c        fork/exec yardımcıları
tests/          birim testleri
```

`make test` protokol ayrıştırıcılarını, kayıt bölmeyi, checksum kodunu ve
listeleri gerçekten çalıştırarak test ediyor. En kritik iki invaryant orada
kontrol ediliyor: HTTP header işleme uzunluğu değiştirmiyor, ve TLS kayıt bölme
ya uzunluğu birebir koruyor ya da hiç dokunmuyor.

Mac'in yoksa `./scripts/crossbuild.sh` Linux'ta gerçek bir Mach-O binary
üretiyor. Zig'in C derleyicisi Darwin başlıklarının çoğunu taşıyor; eksik dördü
(`net/if_utun.h`, `net/bpf.h`, `sys/sys_domain.h`, `netinet/ip6.h`) Apple'ın
açık kaynak XNU deposundan çekiliyor, yani derleme gerçek tanımlara karşı
yapılıyor. Üretilen binary imzasız ve donanımda test edilmemiş olur; Mac'te
`make` kullan.

---

## Lisans ve sorumluluk

Bu araç kendi makinendeki trafiğin nasıl biçimlendiğini kontrol etmen için.
Bağlandığın ağın kurallarına uymak sana ait.
