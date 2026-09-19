# libgcrypt bundle — CryptoAPI notu

`libgcryptbundle11241/bin/*.dll` ve `libgcryptbundle11241/lib/*.lib` **git'e commit edilmiyor**
(`.gitignore`'daki genel `*.dll`/`*.lib` kuralları bu klasörü de kapsıyor). Bu dosyalar **yerel
olarak indirilip/üretilmesi gereken** build artifact'lardır — bu repo'yu taze checkout eden
herkesin, `CLibgcryptProvider`'ı kullanan bir MSVC projesini (AppBuilder, ...) x64 derlemeden
önce bu adımları kendisi çalıştırması gerekir. Header'lar (`include/*.h`) ve `.def` dosyası
commit'e giriyor, DLL/`.lib` girmiyor.

## x64 only

Bu provider **yalnızca x64** için gerçek çalışıyor. Win32'de gerçek bir libgcrypt binary'si
olmadığı için `CLibgcryptProvider` Win32 derlemesinde de var olur ama her metod, CNG'nin
desteklemediği algoritmalar için yaptığı gibi dürüstçe "unsupported" döner — çökme yok, yanlış
sonuç yok, sadece boş destek. Bir Win32 binary bulunursa `LibgcryptProvider.cpp`'nin başındaki
`ARCH_X64`/`ARCH_WIN64` guard'ı ve `AppBuilder.vcxproj`'daki x64-only `ItemDefinitionGroup`'un
Win32 kopyası eklenmesi yeterli.

## Nereden indirilir

Wireshark, Windows build'leri için libgcrypt'i zaten derleyip paketliyor:

https://dev-libs.wireshark.org/windows/packages/libgcrypt/

Kullanılan paket: **`libgcrypt-bundle-1.12.4-1-x64-mingw-dynamic-ws.7z`** — MSYS2'nin
clang64 (UCRT tabanlı) toolchain'iyle derlenmiş, MinGW runtime bağımlılığı olmayan (yalnızca
`api-ms-win-crt-*.dll` + `ADVAPI32`/`USER32`/`KERNEL32`) temiz bir DLL seti.

## Yeniden kurulum adımları

1. Yukarıdaki `.7z` dosyasını indirip açın; içeriği (`bin/`, `include/`, `lib/`, `README.Wireshark`)
   `3rdParty/libgcryptbundle11241/` altına kopyalayın.
2. Paketin kendi `lib/libgcrypt-20.lib` / `lib/libgpg-error-0.lib` dosyaları **GNU ar-format
   `.dll.a` dosyalarının `.lib` uzantısıyla yeniden adlandırılmış hali** — MSVC'nin `link.exe`'si
   bunları doğrudan okuyamaz (`file` komutu ikisini de "current ar archive" gösterir, format farkı
   ayırt edilmez). Gerçek MSVC-uyumlu import lib'i kendiniz üretmeniz gerekir:

   Visual Studio Developer Command Prompt / PowerShell'de (`cl.exe`/`lib.exe`/`dumpbin.exe`
   PATH'te):

   ```bat
   cd 3rdParty\libgcryptbundle11241

   :: 1) DLL'in export tablosundan bir .def dosyası üret
   dumpbin /exports bin\libgcrypt-20.dll > exports.txt
   :: exports.txt'teki "ordinal hint RVA name" satırlarının altındaki isim sütununu
   :: (PowerShell'de: Select-String ile "name" grubunu çekip) lib\libgcrypt-20.def'e
   :: "LIBRARY libgcrypt-20" + "EXPORTS" başlığı altında, bir isim bir satır olacak şekilde yazın.

   :: 2) .def'ten gerçek MSVC import lib'i üret
   lib /def:lib\libgcrypt-20.def /out:lib\libgcrypt-20-msvc.lib /machine:x64
   ```

   Bu adımın çıktısı doğrulanmış: bir `gcry_check_version` çağıran basit bir `test.c`, bu
   `.lib`'e karşı `cl.exe` ile derlenip linklenip başarıyla çalıştırıldı (2026-09-19).

3. `AppBuilder.vcxproj`'daki x64-only `ItemDefinitionGroup` zaten `libgcrypt-20-msvc.lib`'i
   (NOT `libgcrypt-20.lib`'i) referans alıyor — adları karıştırmayın.
4. `libgpg-error-0.lib` için de aynı GNU-ar-format sorunu geçerli, ama `CLibgcryptProvider`
   şu anki haliyle `gpg-err`/`gpgrt` prefix'li fonksiyonları doğrudan çağırmıyor, o yüzden bu
   dosya için ayrı bir MSVC import lib üretmeye gerek kalmadı. İleride gerekirse aynı
   `dumpbin`/`lib.exe` yöntemi uygulanır.

## Doğrulama

Değişiklikten sonra en az şunu derleyip çalıştırın:

```bat
msbuild projects\msvc\AppBuilder\AppBuilder.vcxproj /p:Configuration=Release /p:Platform=x64
```

`CryptoApiTester::RunLibgcryptProviderAllAlgorithmsTest`'in `"round-trip via factory"` dediğini
doğrulayın (`"correctly unsupported"` değil), ve build çıktısında
`"Copying the libgcrypt runtime DLLs next to the output executable"` post-build adımının
çalıştığını (DLL'lerin `.exe` ile aynı klasöre kopyalandığını) kontrol edin.
