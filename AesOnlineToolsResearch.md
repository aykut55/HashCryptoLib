# AES Online Tool Araştırması — Kullanıcı Tarafından Girilebilen Opsiyonlar

Tarih: 14 Eylül 2026
Amaç: `CryptoApiTester::RunAESTests()` tasarımına girdi olarak, popüler online AES şifreleme/çözme araçlarının kullanıcıya sunduğu tüm konfigürasyon parametrelerini çıkarmak. 39 site tarandı (kullanıcının verdiği liste, tekrarlar hariç); 34'ünden kullanılabilir veri elde edildi.

## Erişilemeyen siteler (5)

| Site | Sorun |
| --- | --- |
| https://inventivehq.com/tools/security/aes-encryption-tool | HTTP 403 Forbidden |
| https://codeshack.io/aes-encrypt-decrypt/ | HTTP 403 Forbidden |
| http://aes.online-domain-tools.com/ | SSL sertifikası süresi dolmuş |
| https://www.calcnationtools.com/developer/aes-encrypt | HTTP 403 Forbidden |
| https://devgearbox.com/tools/aes-encryption | HTTP 403 Forbidden |

Ayrıca **https://encode-decode.com/aes-256-cbc-encrypt-online/** erişildi ama sayfa içeriğinde gerçek araç arayüzü (form elemanları) yoktu, sadece tanıtım metni döndü — kullanılabilir veri çıkarılamadı.

**Önemli metodolojik not:** Bu tarama statik HTML üzerinden yapıldı (JavaScript çalıştırılmadı). Bazı siteler (ör. yoyotools, tulz.org, encipherr, snoq.io, w3schools, devtools.tools) form elemanlarını tamamen JS ile render ediyor olabilir — bu yüzden "minimal/opsiyon yok" görünen bazı sonuçlar aslında "JS render edilmediği için görülemedi" anlamına gelebilir, gerçekten opsiyon eksikliği olmayabilir. Kesinleştirmek için tarayıcı otomasyonuyla (claude-in-chrome) tekrar bakılması gerekir.

## Tüm sitelerde gözlemlenen opsiyonların birleşik (union) listesi

### 1. Key Size (anahtar boyutu)
- 128 / 192 / 256 bit (en yaygın üçlü — neredeyse her zengin araçta var)
- Bazı basit araçlarda sabit (genelde 256 bit'e sabitlenmiş)

### 2. Cipher Mode
Gözlemlenen tüm mod değerleri (birleşik):
- **ECB**, **CBC** (en yaygın ikili, hemen her sitede var)
- **CFB**, **OFB**, **CTR** (ikinci en yaygın grup)
- **GCM**, **CCM** (authenticated modes — zengin araçlarda)
- **CTS** (Cipher Text Stealing — sadece toolhelper.cn'de görüldü)
- **KCV** (Key Check Value — sadece hsmkit'te, aslında bir "mode" değil ama dropdown'da mode gibi sunulmuş)
- **EAX** (sadece infyways.com'un açıklama metninde geçti, gerçek dropdown'da görülmedi)

### 3. Padding Scheme
- **PKCS7** / **PKCS5Padding** (evrensel, hemen her yerde)
- **NoPadding** / **None**
- **ZeroPadding** / **Zeros**
- **ANSIX923** / **AnsiX923**
- **ISO10126** / **Iso10126**
- **ISO97971** / **Iso97971**

### 4. IV / Nonce
- Manuel giriş (metin kutusu)
- Otomatik üretim ("Generate"/"New IV" butonu)
- Format seçimi: **Hex**, **Base64**, **UTF-8/Text**
- Mode'a göre boyut farkı: GCM için 12 byte, CBC/CTR için 16 byte, ECB için gereksiz (bazı araçlar bunu otomatik ayarlıyor)
- CCM/GCM'de ayrıca **AAD (Additional Authenticated Data)** alanı

### 5. Authenticated Encryption (GCM/CCM) ekstra parametreleri
- **Tag Length**: 96 / 104 / 112 / 120 / 128 bit (gözlemlenen değerler)
- **AAD** alanı (opsiyonel, hex/base64/utf8 encode edilebilir)
- **Append Tag** toggle'ı (tag'in ciphertext'e eklenip eklenmeyeceği)

### 6. Key Girişi / Key Derivation
- **Raw key** (doğrudan anahtar): Hex / Base64 / UTF-8(Text) formatında
- **Passphrase (parola) + KDF**: en zengin araçlarda (emn178, toolmatic.net) şu KDF seçenekleri var:
  - **PBKDF2** (iterasyon sayısı + salt + hash algoritması seçilebilir: MD5/SHA1/SHA224/SHA256/SHA384/SHA512/RIPEMD160/KECCAK512)
  - **EvpKDF** (OpenSSL'in eski KDF'i)
  - **HKDF** (info/context alanı ile)
  - **Scrypt** (Cost N / Block Size r / Parallelism p / Memory Size parametreleriyle)
  - **Argon2** (mode seçimiyle — 2i/2d/2id gibi)
- Basit araçların çoğu **sabit** PBKDF2-SHA256 kullanıyor (100.000–250.000 iterasyon arası, sabit), kullanıcı sadece parolayı giriyor.

### 7. Salt
- Manuel giriş (hex)
- Otomatik random üretim (16 byte tipik)
- Çıktıya gömülü format: `salt || iv || ciphertext` (base64) — birkaç sitede (base64.sh, w3schools, devtools.tools) bu format sabit.

### 8. Input (girdi) formatı
- **Plain text / UTF-8**
- **Hex**
- **Base64**
- Zengin araçlarda ayrıca: UTF-16LE, UTF-16BE, ISO-8859 varyantları, Windows code page'leri, Doğu Asya kodlamaları (emn178, testmuai)
- **File upload** (bazı araçlarda dosya şifreleme desteği var — toolkk, infyways, aesencryptiondecryption.tool-kit.dev)
- **URL'den içerik çekme** (emn178, testmuai)

### 9. Output (çıktı) formatı
- **Hex** (bazen Lower/Upper Case ayrımı da var)
- **Base64**
- Bazı araçlarda çift yönlü "swap" butonu (hex↔base64)

### 10. Diğer/nadir opsiyonlar
- Algoritma seçimi (AES dışında): AES / TripleDES / Rabbit / RC4 / DES (qr9.net) — bu SDK'nın kapsamı dışında ama "provider seçimi" fikrini destekliyor
- "OpenSSL format" toggle'ı (Salted__ prefix'i ekleyip eklememe) — emn178, toolmatic.net
- Preset seçimi: "OpenSSL (CBC)", "Node crypto (GCM)", "Web Crypto (GCM)", "CryptoJS (CBC)", "Custom" (coderstool.com) — yani hazır "profil" seçme fikri

## Site bazlı özet tablo

| Site | Zenginlik | Mode | Key Size | Padding | IV | Encoding | Not |
| --- | --- | --- | --- | --- | --- | --- | --- |
| devglan.com | Yüksek | ECB/CBC/CTR/GCM | 128/192/256 | NoPadding/PKCS5 | ✓ (+format) | Base64/Hex | GCM tag length 96-128 |
| emn178.github.io (encrypt/decrypt) | **En yüksek** | CBC/CTR/CFB/OFB/ECB/GCM/CCM | 128/192/256 | 7 çeşit | ✓ + AAD + nonce | 20+ encoding | 5 farklı KDF, OpenSSL format toggle |
| coderstool.com | Yüksek | CBC/CCM/CFB/CTR/GCM/OFB | 128/192/256 | — | ✓ | — | Preset seçimi (OpenSSL/Node/WebCrypto/CryptoJS) |
| qr9.net | Orta-Yüksek | CBC/CFB/CTR/OFB/ECB | Auto/128/192/256 | 6 çeşit | ✓ | Utf8/Hex/Base64 | Algoritma seçimi de var (AES/3DES/Rabbit/RC4/DES) |
| hsmkit.com | Orta-Yüksek | ECB/CBC/CFB/OFB/KCV | 128/192/256 | — | ✓ | ASCII/Hex | — |
| anycript.com | Orta | CBC/ECB | 128/192/256 | — | ✓ | Base64/Hex | — |
| javainuse.com | Orta | CBC/ECB | 128/192/256 | — | ✓ | Base64/Hex | — |
| base64.sh | Düşük-Orta | GCM/CBC | 128/256 | — | otomatik | Base64/Hex | Parola tabanlı, PBKDF2 sabit |
| toolhelper.cn | Yüksek | CBC/ECB/OFB/CFB/CTS/CTR | 128/192/256 | 5 çeşit | ✓+nonce+AAD | Utf8/Hex/Base64 | CTS moduna sahip nadir site |
| testmuai.com | **Çok Yüksek** | EBC/CBC/CTR/GCM (+CCM ima) | 128/192/256 | Pkcs5/NoPadding | ✓ | çok sayıda encoding | emn178 ile aynı motor gibi |
| toolkk.com | Orta | ECB/CBC | 128/192/256 | dropdown var (detay yok) | ✓ auto-gen | Hex/Base64 | — |
| angrytools.com | Orta-Yüksek | ECB/GCM/CFB/OFB/CTR/CBC | key uzunluğuna göre | — | ✓ | Hex/Base64 | Snippet/kod üretimi de var |
| credenshare.io | Düşük | GCM/CBC | 256 sabit | — | otomatik | Base64 | Parola tabanlı |
| aesencryptiondecryption.tool-kit.dev | Orta | ECB/CBC/CFB/OFB | 128/192/256 | — | ✓ opsiyonel | Base64/Hex | — |
| h.markbuild.com | Orta | CBC/ECB/CFB/OFB/CTR | — | 6 çeşit | ✓ zorunlu | — | Key size dropdown'u görünmedi |
| infyways.com | Orta-Yüksek | CBC/CFB/OFB/ECB | 128/192/256 | dropdown var | ✓ toggle+generate | Base64/Hex | — |
| toolmatic.net | **Çok Yüksek** | GCM/CBC/CTR/ECB | 128/192/256 | PKCS7 (oto) | ✓ mode'a göre boyut | Base64/Hex | PBKDF2 iterasyon+salt, AAD, tag length 96/112/128 |
| monkeydev.net | Orta | CBC/ECB/CFB/CTR/OFB | — | PKCS7/Zero/NoPadding+ | ✓ hex | — | — |
| toolswise.com | Orta-Yüksek | CBC/ECB/CTR | 128/192/256 | 5 çeşit | ✓ opsiyonel+generate | Base64/Hex | — |
| testprotect.com (AEScalc) | Çok Düşük | — (sadece 128-bit) | 128 sabit | — | — | Hex sabit | FIPS-197 test vektörü hesaplayıcı |
| diğerleri (yoyotools, encipherr, tulz.org, snoq.io, w3schools, devtools.tools, cryptii.com, alvandsoft, encode-decode.com) | Düşük/Minimal | çoğunlukla sabit (GCM veya CBC) | çoğunlukla 256 sabit | görünmüyor | otomatik | Base64 çoğunlukla | Basit "metin + parola" arayüzü; JS-render nedeniyle eksik olabilir |

## `RunAESTests()` tasarımı için çıkarımlar

Bu araştırmaya göre, kapsamlı bir AES test matrisi şu boyutları içermeli:

1. **Key size**: 128 / 192 / 256 (zaten `AeadAlgorithm`/`LegacySymmetricAlgorithm` enum'larında var)
2. **Mode**: ECB/CBC/CFB/OFB/CTR (Legacy) + GCM/CCM/EAX/SIV (AEAD) — zaten enum'larda var
3. **Padding**: PKCS7 vs NoPadding vs ZeroPadding — şu an SDK'da seçilemiyor, Legacy cipher'lar sabit padding kullanıyor (CBC/ECB PKCS7-benzeri, stream modları padding'siz)
4. **IV/Nonce**: manuel vs otomatik üretim — SDK zaten otomatik üretiyor (`IRandomSource`), manuel IV girişi şu an desteklenmiyor
5. **Key girişi**: raw key vs passphrase+KDF — SDK'da ikisi de var (`EncryptBuffer` parola, Factory seviyesinde `SetKey` raw key)
6. **KDF çeşitliliği**: PBKDF2 dışında Scrypt/Argon2/HKDF — SDK şu an sadece PBKDF2-SHA256 kullanıyor, kapsam dışı olabilir
7. **Encoding**: input/output Hex/Base64/UTF-8 — SDK ham byte buffer kullanıyor, encoding SDK'nın işi değil (çağıran taraf hallediyor), test tasarımında bunu göz önünde bulundurmaya gerek yok
8. **GCM tag length**: değişken (96-128 bit) — SDK şu an sabit 128-bit tag kullanıyor, bu bir genişletme fırsatı olabilir

Bu liste, birlikte tasarlayacağımız `RunAESTests()` metodunun hangi parametre kombinasyonlarını (key size × mode × padding × ...) test edeceğine karar vermek için başlangıç noktası.
