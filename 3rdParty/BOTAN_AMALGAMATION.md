# Botan amalgamation — CryptoAPI notu

`botan3130/x64/botan_all.h`, `botan3130/x64/botan_all.cpp`, `botan3130/Win32/botan_all.h`,
`botan3130/Win32/botan_all.cpp` **git'e commit edilmiyor** (`.gitignore`'daki genel
`x64/`/`Win32/` kuralları bu klasörleri de kapsıyor). Bu dosyalar Botan'ın `configure.py`
scriptiyle **yerel olarak üretilmesi gereken** build artifact'lardır — bu repo'yu taze checkout
eden herkesin, `CBotanProvider`'ı kullanan herhangi bir MSVC projesini (AppBuilder, DllBuilder,
LibBuilder, ...) derlemeden önce bu adımı kendisi çalıştırması gerekir.

## Neden RSA modülü önemli

`CBotanProvider`'ın RSA-OAEP-SHA256 desteği (`IAsymmetricCipher`) için amalgamation'ın `rsa` VE
`eme_oaep` modülleriyle üretilmiş olması şart. `eme_oaep`, Botan'ın modül sisteminde `rsa`'nın
`requires` listesindeki `enc_padding`'den **ayrı, kendi başına aktive edilmesi gereken bir alt
modül**dür — sadece `rsa` eklemek yeterli değildir; `enc_padding` derlenir ama concrete OAEP
implementasyonu (`BOTAN_HAS_EME_OAEP`) derlenmeden kalır ve `PK_Encryptor_EME` runtime'da
`"OAEP(SHA-256)"` algoritmasını bulamayıp `Algorithm_Not_Found` fırlatır (`GetMaxPlaintextSize`
sessizce 0 döner, `GenerateKeyPair` sonrası her şey "unsupported" gibi görünür).

## Yeniden üretme komutları

Visual Studio Developer Command Prompt / PowerShell'de (yani `cl.exe` PATH'te),
`3rdParty/botan3130` klasöründe çalıştırın:

```bat
:: x64
python configure.py --amalgamation --minimized-build --disable-shared ^
  --enable-modules=aes,camellia,serpent,twofish,gcm,ccm,eax,siv,gcm_siv,chacha20poly1305,cbc,cfb,ofb,ctr,pbkdf2,hmac,sha2_32,sha2_32_x86,sha2_32_simd,sha2_32_avx2,system_rng,auto_rng,mode_pad,rsa,eme_oaep,md5,sha1,sha2_64,sha3,blake2,blake2s,rmd160,ecdsa,ec_group,ecc_key,pcurves_secp256r1,ed25519,emsa_pssr,mgf1,pem ^
  --cpu=x86_64
move /Y botan_all.h x64\botan_all.h
move /Y botan_all.cpp x64\botan_all.cpp
del botan_all.obj

:: Win32
python configure.py --amalgamation --minimized-build --disable-shared ^
  --enable-modules=aes,camellia,serpent,twofish,gcm,ccm,eax,siv,gcm_siv,chacha20poly1305,cbc,cfb,ofb,ctr,pbkdf2,hmac,sha2_32,sha2_32_x86,sha2_32_simd,sha2_32_avx2,system_rng,auto_rng,mode_pad,rsa,eme_oaep,md5,sha1,sha2_64,sha3,blake2,blake2s,rmd160,ecdsa,ec_group,ecc_key,pcurves_secp256r1,ed25519,emsa_pssr,mgf1,pem ^
  --cpu=x86_32
move /Y botan_all.h Win32\botan_all.h
move /Y botan_all.cpp Win32\botan_all.cpp
del botan_all.obj
```

`sha2_32_x86`/`sha2_32_simd`/`sha2_32_avx2` hızlandırma modülleri olmadan SHA-256
tamamen yazılım (donanım hızlandırmasız) çalışır — bu SDK'nın parola tabanlı tüm
şifreleme yollarının kullandığı 600.000 iterasyonluk PBKDF2'yi ~1 dakikaya kadar
yavaşlatabilir (birden fazla türetme yapan bir akışta bu dakikalarca sürebilir ve
"kilitlenmiş" gibi görünür). Botan bu modüller arasından çalışma zamanında CPUID
ile en uygununu seçer, o yüzden üçünü de sorgusuz eklemek güvenli.

`configure.py` amalgamation çıktısını her zaman çalıştırıldığı dizinin köküne yazar
(`--with-build-dir` bu davranışı değiştirmez); bu yüzden yukarıdaki `move` adımları gerekli.

## Hash modülleri (2026-09-15)

`CBotanProvider`'ın `IHashService` desteği için `md5,sha1,sha2_64,sha3,blake2,blake2s,rmd160`
modülleri eklendi (mevcut `sha2_32` zaten SHA-224/256'yı kapsıyordu). Not: `md5` modülü Botan
tarafından "Deprecated" olarak işaretleniyor (configure.py çıktısında sarı uyarı basıyor) ama
derlemeyi engellemiyor -- sadece MD5'in kriptografik olarak kırık olduğuna dair standart bir
uyarı, kod tarafında ekstra bir işlem gerektirmiyor. `x86_32` (Win32) hedefinde `sha2_64_avx2`/
`sha2_64_x86` gibi CPU-özel hızlandırma modülleri otomatik atlanıyor (32-bit'te uygulanamaz),
tıpkı `sha2_32_avx2`'nin Win32'de atlanması gibi -- bu beklenen davranış, hata değil.

## Signature (imza) modülleri (2026-09-15)

`CBotanProvider`'ın `ISignatureEngine` desteği (RSA-PSS-SHA256, ECDSA-P256-SHA256, Ed25519) için
`ecdsa,ec_group,ecc_key,pcurves_secp256r1,ed25519,emsa_pssr,mgf1,pem` modülleri eklendi. Yine aynı
gotcha ile karşılaşıldı:

- `rsa` modülü `sig_padding`'i (soyut dispatcher) otomatik çekiyor ama concrete PSS implementasyonu
  (`emsa_pssr`, dizin adı da bu) ayrı eklenmesi gerekiyor -- tıpkı `eme_oaep`'in `enc_padding`'den
  ayrı olması gibi.
- `ecdsa` modülü `ec_group`/`ecc_key`'i **otomatik çekmiyor**, `<requires>` listesinde varlar ama
  `--enable-modules`'e elle eklenmesi gerekiyor.
- `ec_group` kendisi de `pcurves`'e bağımlı (Botan 3.13'te EC_Group artık pcurves backend'ini
  kullanıyor) ama `pcurves`'in kendisi `--enable-modules`'e **doğrudan eklenemiyor**
  ("Module 'pcurves' is meant for internal use only" hatası) -- sadece somut eğri modülünü
  (`pcurves_secp256r1`, P-256 için) eklemek yeterli, `pcurves` ve `pcurves_impl` otomatik geliyor.
- `ed25519` modülü tek başına yeterli (sadece `sha2_64`'e bağımlı, o zaten hash çalışmasından beri
  ekli).

## Modül listesini genişletirken

Yeni bir Botan algoritması/özelliği wire edilecekse (ör. imza şemaları, ECDH, Argon2), önce
`botan3130/src/lib/<ilgili-dizin>/info.txt` dosyasındaki `<requires>` bölümüne bakın — Botan'da
"üst" modüller (ör. `rsa`) alt implementasyon modüllerini (ör. `eme_oaep`) otomatik çekmez,
sadece soyut dispatcher'ı (`enc_padding`) çeker. Her concrete algoritma/padding/mod'un kendi
modül adını `--enable-modules` listesine açıkça eklemek gerekir; aksi halde derleme geçer ama
runtime'da `Algorithm_Not_Found`/`Lookup_Error` alınır.

## Doğrulama

Değişiklikten sonra en az şunu derleyip çalıştırın:

```bat
msbuild projects\msvc\All\All.sln /t:AppBuilder /p:Configuration=Debug /p:Platform=x64
```

ve `CryptoApiTester::RunBotanProviderAllAlgorithmsTest` içindeki RSA satırlarının
`"round-trip via factory"` dediğini doğrulayın (`"correctly unsupported"` değil).
