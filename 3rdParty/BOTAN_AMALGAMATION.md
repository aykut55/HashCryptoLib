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
  --enable-modules=aes,camellia,serpent,twofish,gcm,ccm,eax,siv,gcm_siv,chacha20poly1305,cbc,cfb,ofb,ctr,pbkdf2,hmac,sha2_32,system_rng,auto_rng,mode_pad,rsa,eme_oaep ^
  --cpu=x86_64
move /Y botan_all.h x64\botan_all.h
move /Y botan_all.cpp x64\botan_all.cpp
del botan_all.obj

:: Win32
python configure.py --amalgamation --minimized-build --disable-shared ^
  --enable-modules=aes,camellia,serpent,twofish,gcm,ccm,eax,siv,gcm_siv,chacha20poly1305,cbc,cfb,ofb,ctr,pbkdf2,hmac,sha2_32,system_rng,auto_rng,mode_pad,rsa,eme_oaep ^
  --cpu=x86_32
move /Y botan_all.h Win32\botan_all.h
move /Y botan_all.cpp Win32\botan_all.cpp
del botan_all.obj
```

`configure.py` amalgamation çıktısını her zaman çalıştırıldığı dizinin köküne yazar
(`--with-build-dir` bu davranışı değiştirmez); bu yüzden yukarıdaki `move` adımları gerekli.

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
