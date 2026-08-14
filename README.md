# dpiOS

macOS için DPI (Deep Packet Inspection) atlatma aracı. Windows'taki
GoodbyeDPI'ın işlevini Apple Silicon üzerinde sağlar: giden bağlantıları, araya
giren filtrenin hedefi çözemeyeceği biçimde yeniden düzenler.

Kernel extension, Apple Developer hesabı veya harici bağımlılık gerektirmez.
Tek bir C programı ve `sudo` yeterlidir.

```bash
cd ~ && git clone https://github.com/ahmethasmerdogan/dpiOS.git 2>/dev/null; \
cd ~/dpiOS && git pull && sudo bash install.sh
```

Depo daha önce indirilmişse aynı komut güncelleyip devam eder.

---

## İçindekiler

- [Genel bakış](#genel-bakış)
- [Kurulum](#kurulum)
- [Sorun giderme](#sorun-giderme)
- [Kapsam](#kapsam)
- [Ayarlar](#ayarlar)
- [Mimari](#mimari)
- [Ölçüm sonuçları](#ölçüm-sonuçları)
- [Geliştirme](#geliştirme)
- [Lisans](#lisans)

---

## Genel bakış

Türkiye'de erişime kapatılan siteler tipik olarak iki ayrı katmanda
engellenmektedir ve her ikisinin de ayrı ayrı çözülmesi gerekir.

**DNS katmanı.** Alan adı sorgusuna sitenin gerçek adresi yerine engelleme
sayfasının adresi döner. Farklı bir DNS sunucusu tanımlamak sonucu
değiştirmez, çünkü sorgunun kendisi yolda değiştirilir; hangi sunucuya
gönderildiği önemli değildir. dpiOS bu katmanı, sorguyu HTTPS içinde taşıyan
yerel bir çözümleyiciyle aşar.

**DPI katmanı.** Adres doğru çözülse bile TLS el sıkışmasında hedef alan adını
taşıyan alan (SNI) açık gider; filtre bunu görüp bağlantıyı sonlandırır. dpiOS
el sıkışmasını, filtrenin ayrıştıramayacağı ancak sunucunun sorunsuz kabul
ettiği biçimde yeniden çerçeveler.

Kurulum betiği her iki katmanı da ölçer ve hangisinin müdahale gerektirdiğine
kendisi karar verir.

---

## Kurulum

**Gereksinimler:** macOS 11 veya üstü, Xcode Command Line Tools. İkincisi kurulu
değilse betik `xcode-select --install` komutunu bildirerek durur.

```bash
sudo bash install.sh
```

Betiğin izlediği adımlar:

1. Kaynağı derler.
2. Gerekli alt sistemlerin çalıştığını doğrular (`--check`).
3. Engelin DNS mi DPI mi olduğunu ölçer.
4. Hangi ayarın sonuç verdiğini deneyerek belirler.
5. Belirlenen ayarla launchd servisini kurar.
6. Sonucu raporlar.

Kurulum sırasında üretilen çıktı şu biçimdedir:

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

Öntanımlı olarak `discord.com` sınanır. Farklı alan adları argüman olarak
verilebilir:

```bash
sudo bash install.sh ornek.com baskasite.com
```

Kurulumun tamamı `/tmp/dpios-install.log` dosyasına yazılır. Hata bildiriminde
paylaşılması gereken tek dosya budur.

### Kaldırma

```bash
sudo bash scripts/uninstall-service.sh
```

Servisi durdurur, pf kurallarını temizler, `/etc/hosts` üzerinde yapılan
eklemeleri geri alır ve kapatılmışsa IPv6'yı yeniden etkinleştirir. `--purge`
argümanı binary ve log dosyasını da siler.

---

## Sorun giderme

Ağ bağlantısı tamamen kesilirse aşağıdaki komut önceki duruma döndürür:

```bash
sudo pfctl -a com.apple/dpios -F all
```

dpiOS normal koşullarda bu temizliği kapanırken kendisi yapar; Ctrl-C, `kill`
ve çökme durumları dahil. Komut yalnızca bunun da gerçekleşmediği durumlar
içindir.

| Belirti | Çözüm |
|---|---|
| `command not found` | Çalışma dizini `dpiOS` değil ya da depo güncellenmemiş. Yukarıdaki tek satırlık komut her ikisini de giderir |
| Site açılmıyor | Sırasıyla `sudo dpios -6`, `-7` ve `-9` denenmelidir |
| Web sürümü açılıyor, masaüstü uygulaması açılmıyor | Uygulama ⌘Q ile tamamen kapatılıp yeniden başlatılmalıdır; pencereyi kapatmak yeterli değildir |
| Tarayıcıda sonuç tutarsız | `sudo dpios -5 --block-quic` — bazı siteler HTTP/3 üzerinden bağlanmayı dener |
| Hiçbir değişiklik gözlenmiyor | `sudo dpios -5 -vv` çıktısında `TLS ClientHello -> alanadi` satırları aranmalıdır |
| VPN etkinken bozuluyor | `--inject raw` eklenmelidir |

Gönderilen paketleri doğrudan incelemek için:

```bash
sudo tcpdump -i en0 -n 'tcp port 443 and host <hedef-ip>'
```

Tek bağlantı için iki ayrı paket görülmesi beklenir.

---

## Kapsam

Doğrulanmış davranış:

- **Web siteleri.** Tarayıcı ve `curl` ile doğrulanmıştır.
- **Masaüstü uygulamaları.** Bu uygulamalar `gateway.us-east1-b.discord.gg`
  gibi çalışma anında öğrenilen adları çözer. Statik bir `/etc/hosts` listesi
  bu adları kapsayamadığı için gerçek bir DNS çözümleyici gerekir; dpiOS bunu
  içerir.
- **Sesli bağlantı.** Engelli görünmemektedir. İlgili sunucular `discord.media`
  alan adı altındadır ve bu alan adı ne DNS ne de DPI katmanında engelli
  çıkmıştır.

Kapsam dışında kalanlar:

- **Gelen paket filtreleme (`-p`).** Dönüş trafiği tasarım gereği dpiOS
  üzerinden geçmez; bu nedenle filtrenin ürettiği sahte RST paketi
  yakalanamaz. Bayrak verildiğinde uyarı üretilir ve yok sayılır.
- **QUIC / HTTP/3.** UDP üzerinden taşındığı için TCP yolunu işleyen dpiOS'a
  uğramaz. `--block-quic` ile UDP/443 kapatılarak istemci TCP'ye
  düşürülebilir; bu seçenek QUIC'i sorunsuz kullanan siteleri de yavaşlattığı
  için öntanımlı olarak kapalıdır.
- **Yer açılamayan ClientHello'lar.** Aşağıda açıklanan beş baytlık alan
  bulunamazsa ilgili bağlantıya müdahale edilmez; paket hiçbir koşulda
  büyütülmez.
- **IPv6.** Deneyseldir (`--ipv6`), öntanımlı olarak kapalıdır.

---

## Ayarlar

Preset numaraları GoodbyeDPI ile aynıdır.

| Preset | İşlev |
|---|---|
| `-1`…`-4` | HTTP odaklı hafif müdahaleler |
| `-5` | Önerilen başlangıç. TLS kayıt bölme, parçalama ve otomatik TTL'li sahte paket |
| `-6` | Sahte paket geçersiz sequence numarasıyla gönderilir |
| `-7` | Sahte paket geçersiz checksum ile gönderilir |
| `-8` | `-6` ve `-7` birlikte |
| `-9` | `-8` yapılandırmasına ek olarak bölme noktası alan adının ortasına alınır |

Kurulum betiği bu ayarları hedef bağlantı üzerinde sınayıp sonuç vereni
seçtiğinden, elle seçim normalde gerekmez.

Sık kullanılan bayraklar:

```
--doh              şifreli DNS çözümleyiciyi çalıştırır (127.0.0.1:53)
--record-frag      ClientHello'yu iki TLS kaydına böler (öntanımlı açık)
--frag-sni         bölme noktasını alan adının ortasına alır
--block-quic       UDP/443'ü kapatır, istemciyi TCP'ye düşürür
--blacklist FILE   yalnızca listedeki alan adlarına müdahale eder
--whitelist FILE   listedeki alan adlarına müdahale etmez
--dry-run          tespit eder ve kaydeder, değişiklik yapmaz
--check            alt sistemleri doğrular ve çıkar
--unload           artakalan pf kurallarını temizler ve çıkar
-vv                paket düzeyinde kayıt
```

Tam liste için `dpios --help`.

Liste dosyalarında satır başına bir alan adı yazılır. `#` ile başlayan satırlar
yorumdur; `0.0.0.0 alanadi` biçimi ve baştaki `*.` kabul edilir. Eşleşme alt
alan adlarını kapsar: `example.com` girdisi `www.example.com` ile eşleşir,
`notexample.com` ile eşleşmez.

Terminalde çalıştırıldığında akan kayıt yerine yerinde güncellenen bir durum
paneli çizilir. `-vv` verildiğinde veya servis olarak çalıştırıldığında düz
kayda geçer.

---

## Mimari

GoodbyeDPI, Windows'ta WinDivert sürücüsüyle paketleri çekirdek düzeyinde
yakalar. macOS'ta eşdeğer bir sürücü bulunmadığı ve Apple Silicon'da kext
geliştirme yolu pratikte kapalı olduğu için dpiOS aynı işlevi işletim
sisteminin kendi bileşenlerini birleştirerek sağlar:

```
  uygulama
     │
     ▼
  kernel TCP/IP            ← kaynak adres burada seçilir
     │
     ▼
  pf: route-to utunN       ← yalnızca TCP 80/443, yalnızca dışa çıkan
     │
     ▼
  utun ──────────────▶  dpios
                          │  ClientHello iki TLS kaydına bölünür
                          │  TCP segmentine bölünür, sıra ters çevrilir
                          │  sahte paket üretilir
                          ▼
                       /dev/bpf ──▶ en0 ──▶ internet

  dönüş trafiği: en0 ──▶ kernel   (dpios üzerinden geçmez)
```

Mimariyi üç karar belirler.

**Öntanımlı rota değiştirilmez.** `pf route-to` yalnızca ilgilenilen trafiği
utun arayüzüne yönlendirir. Kaynak adres değişmediği için NAT katmanına gerek
kalmaz.

**Dönüş trafiği işlenmez.** Bağlantıyı çekirdek zaten tanır. Bu, başarım
açısından avantajlıdır; karşılığında gelen paketlere müdahale edilemez.

**Paket uzunluğu değiştirilmez.** Çekirdek, ilgili sequence numarasında tam N
bayt gönderdiğini varsayar. Bir bayt eksik veya fazla göndermek akışı bozar ve
dönüş yolu işlenmediği için düzeltilemez. Bu kısıt iki noktada belirleyicidir:

- `-s` (Host başlığından sonraki boşluğun silinmesi) ve `-a` (metot ile URI
  arasına boşluk eklenmesi) daima birlikte uygulanır. Biri bir bayt eksiltir,
  diğeri bir bayt ekler.
- TLS kayıt bölme, ikinci kayıt için beş baytlık ek başlık gerektirir. Bu beş
  bayt ClientHello'nun içinden geri kazanılır: padding uzantısı (RFC 7685)
  küçültülür veya bir GREASE uzantısı (RFC 8701) çıkarılır. Her ikisi de
  sunucunun yok saymakla yükümlü olduğu alanlardır. Uygun alan bulunamazsa
  bağlantıya müdahale edilmez.

Paketler `/dev/bpf` üzerinden ham ethernet çerçevesi olarak gönderilir. Bu yol
yönlendirme tablosunu ve pf çıkış zincirini atladığından, üretilen paketler
tekrar utun arayüzüne düşerek döngü oluşturmaz.

---

## Ölçüm sonuçları

Aşağıdaki bulgular bir Türkiye operatörü üzerinde ölçülmüştür.

### DNS katmanı

Sistem çözümleyicisi `discord.com` için `195.175.254.2` döndürmektedir; gerçek
adres `162.159.136.232`. Sorgu, hedef sunucudan bağımsız olarak
değiştirilmektedir:

| Sorgu yolu | `example.com` | `discord.com` |
|---|---|---|
| `1.1.1.1` UDP/53 | yanıt | zaman aşımı |
| `1.1.1.1` TCP/53 | yanıt | RST |
| DoH (şifreli) | yanıt | gerçek adres |

Filtre alan adına duyarlı, harf büyüklüğüne duyarsızdır; DNS 0x20
rastgeleleştirmesi sonucu değiştirmemiştir. Ayrıca joker karakterli
çalışmaktadır: `rastgele-isim.discord.gg` gibi var olmayan bir ad da engelleme
sayfasına yönlendirilmektedir. Statik bir `/etc/hosts` listesinin masaüstü
uygulamaları için yetersiz kalmasının nedeni budur.

### DPI katmanı

Adres doğru çözüldüğünde dahi TLS el sıkışması yaklaşık 14 ms içinde RST
almaktadır. Denenen yöntemler:

| Yöntem | Sonuç |
|---|---|
| Müdahalesiz (kontrol) | RST |
| TCP'de ikinci bayttan bölme | RST |
| TCP'de alan adının ortasından bölme | RST |
| Alan adının harf büyüklüğünü değiştirme | RST |
| SNI uzantısını listenin sonuna alma | RST |
| **İki TLS kaydına bölme** | **ServerHello** |

Sonuç, filtrenin TCP akışını birleştirdikten sonra incelediğini
göstermektedir; segment düzeyinde bölme etkisizdir. Kayıt düzeyinde bölme
etkilidir, çünkü bir handshake mesajının birden çok kayda yayılması TLS
belirtimine uygundur ve yalnızca ilk kaydı ayrıştıran bir denetleyici mesajın
tamamını göremez.

Bu davranış dpiOS'un ürettiği paketlerle doğrulanmıştır. Üç ClientHello
biçiminde de müdahalesiz paket RST, müdahale edilmiş paket ServerHello
almaktadır: tek segmente sığan hello, Chromium'unki gibi iki segmente taşan
hello ve padding uzantısı segment sınırını aşan hello. Üç durumda da toplam
uzunluk korunmaktadır.

---

## Geliştirme

```
install.sh      kurulum ve teşhis betiği
src/
  main.c        kqueue döngüsü, sinyaller, kurulum ve temizlik sırası
  cli.c         argüman ayrıştırma
  config.c      öntanımlı değerler ve preset'ler
  check.c       --check self-test
  ui.c          canlı durum paneli
  dns.c         şifreli DNS çözümleyici
  utun.c        utun arayüzü (PF_SYSTEM kernel control)
  pf.c          pf kurallarının yüklenmesi ve temizlenmesi
  inject.c      BPF ve raw socket enjektörleri
  netinfo.c     rota, arayüz ve ARP/NDP tablosu
  monitor.c     pasif TTL gözlemcisi
  engine.c      DPI atlatma mantığı
  tls.c         ClientHello ayrıştırma ve TLS kayıt bölme
  http.c        HTTP başlık işleme
  blacklist.c   alan adı listeleri
  checksum.c    IPv4/IPv6/TCP/UDP checksum
  util.c        fork/exec yardımcıları
tests/          birim testleri
```

`make test` protokol ayrıştırıcılarını, kayıt bölmeyi, checksum kodunu ve liste
işlemlerini çalıştırarak sınar. İki invaryant burada doğrulanır: HTTP başlık
işleme toplam uzunluğu değiştirmez ve TLS kayıt bölme ya uzunluğu birebir korur
ya da hiç müdahale etmez.

macOS erişimi olmayan ortamlarda `./scripts/crossbuild.sh` geçerli bir Mach-O
binary üretir. Zig'in C derleyicisi Darwin başlıklarının çoğunu içerir; eksik
dördü (`net/if_utun.h`, `net/bpf.h`, `sys/sys_domain.h`, `netinet/ip6.h`)
Apple'ın açık kaynak XNU deposundan alınır, dolayısıyla derleme gerçek
tanımlara karşı yapılır. Üretilen binary imzasızdır ve donanım üzerinde
sınanmamıştır; macOS üzerinde `make` kullanılmalıdır.

---

## Lisans

Bu araç, kullanıcının kendi makinesindeki ağ trafiğinin nasıl biçimlendiğini
denetlemesi amacıyla geliştirilmiştir. Bağlanılan ağın kullanım koşullarına
uyum kullanıcının sorumluluğundadır.
