# Python embed (pybind11 + CPython) — CryptoAPI notu

`3rdParty/scripts/python312/bin/*.dll`, `*.pyd` ve `3rdParty/scripts/python312/libs/python312.lib`
**git'e commit edilmiyor** (`.gitignore`'daki genel `*.dll`/`*.lib` kuralları + `*.pyd` için özel
satır bu klasörü kapsıyor) — libgcrypt bundle ile birebir aynı politika, bkz.
`3rdParty/LIBGCRYPT_BUNDLE.md`. Header'lar (`python312/Include/*.h`) commit'e giriyor; onlar
build artifact değil, doğrudan CPython kaynak ağacından kopyalanmış sabit dosyalar.
`3rdParty/scripts/pybind11310/` (header-only) tamamen commit'e giriyor, hiçbir dosyası
gitignore'da değil.

## x64 only

`CPythonScriptEngine` **yalnızca x64** için gerçek çalışıyor. python.org'un Windows embeddable
paketi yalnızca amd64 binary'leri yayınlıyor, Win32/x86 build'i yok. Win32 derlemesinde de
`CPythonScriptEngine` var olur ama `PythonScriptEngine.cpp`'nin başındaki `ARCH_X64`/`ARCH_WIN64`
guard'ı (`LibgcryptProvider.cpp`'nin kendi guard'ıyla birebir aynı desen) yüzünden hiçbir
pybind11/Python header'ı derlemeye girmez — `RunFile`/`RunString` `NOT_IMPLEMENTED` fırlatır,
`GetGlobalBool`/`GetGlobalInt`/`GetGlobalString` sırasıyla `false`/`0`/boş string döner. Çökme yok,
yanlış sonuç yok, sadece dürüst "desteklenmiyor".

## Kullanılan sürümler

- **pybind11 v3.1.0** — https://github.com/pybind/pybind11/releases/tag/v3.1.0 (`archive/refs/tags/v3.1.0.zip`)
- **CPython 3.12.10** — https://www.python.org/ftp/python/3.12.10/ — 3.12 serisinin, hem
  "Windows embeddable package" hem de kaynak tarball'ının ikisinin birden yayınlandığı **son**
  patch sürümü (3.12.11'den itibaren 3.12 yalnızca kaynak/güvenlik yaması olarak çıkıyor, artık
  Windows binary paketi yok — bu yüzden 3.12.14 değil 3.12.10 kullanıldı).

## Nereden/nasıl indirildi

pybind11 header-only; doğrudan GitHub release zip'inden `include/pybind11/` ağacı ve `LICENSE`
alındı, başka hiçbir şey gerekmedi:

```bat
curl -sL -o pybind11-3.1.0.zip https://github.com/pybind/pybind11/archive/refs/tags/v3.1.0.zip
:: aç, include/pybind11 -> 3rdParty/scripts/pybind11310/include/pybind11, LICENSE -> yanına kopyala
```

CPython tarafı üç ayrı parçadan birleştirildi — python.org'un embeddable paketi DLL+stdlib'i
veriyor ama header'ları ve import lib'i **vermiyor**; bunları tam bir Windows installer kurmadan
elde etmenin pratik yolu şu:

1. **DLL + zip'lenmiş stdlib** — resmi "Windows embeddable package":
   ```bat
   curl -sL -o python-3.12.10-embed-amd64.zip https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip
   ```
   Bu zip'in TÜM içeriği (`python312.dll`, `python3.dll`, `python312.zip` — zip'lenmiş stdlib,
   her `_xxx.pyd` extension modülü, `vcruntime140*.dll`, `libssl-3.dll`, `libcrypto-3.dll`,
   `libffi-8.dll`, `sqlite3.dll`, ...) `3rdParty/scripts/python312/bin/` altına kopyalandı.
   `AppBuilder.vcxproj`'daki PostBuildEvent bu klasördeki `*.dll`/`*.pyd`/`python312.zip`'i derleme
   çıktısının (`$(OutDir)`) yanına kopyalıyor — embed paketi zaten "DLL'in yanına at, çalışır"
   şeklinde tasarlanmış, `Lib/` klasörüne ihtiyaç yok.

2. **Header'lar** — embeddable pakette YOK; CPython kaynak tarball'ından alındı:
   ```bat
   curl -sL -o Python-3.12.10.tar.xz https://www.python.org/ftp/python/3.12.10/Python-3.12.10.tar.xz
   tar -xJf Python-3.12.10.tar.xz Python-3.12.10/Include Python-3.12.10/PC/pyconfig.h Python-3.12.10/LICENSE
   ```
   `Include/*.h` (ve `Include/cpython/`, `Include/internal/`) doğrudan
   `3rdParty/scripts/python312/Include/` altına, `PC/pyconfig.h` (Windows'a özel, `configure`
   çalıştırmadan doğrudan kullanılabilir hazır header) da aynı klasöre `pyconfig.h` adıyla
   kopyalandı — CPython'un kendi build sistemi de tam olarak bunu yapıyor (PC/pyconfig.h,
   Include/ ile aynı klasöre kopyalanıp derleniyor).

3. **Import lib** (`python312.lib`) — embeddable pakette YOK, kaynak tarball'ında da YOK (o da bir
   installer/build çıktısı). Tam bir Windows installer kurmadan, doğrudan elde etmenin yolu:
   `python312.dll`'in kendi export tablosundan bir `.def` dosyası türetip `lib.exe` ile gerçek bir
   MSVC-native import lib üretmek — libgcrypt bundle'daki `libgcrypt-20-msvc.lib` için izlenen
   YÖNTEMİN BİREBİR AYNISI, bkz. `3rdParty/LIBGCRYPT_BUNDLE.md`:

   ```bat
   :: Visual Studio Developer Command Prompt'ta (dumpbin.exe/lib.exe PATH'te)
   dumpbin /exports python312.dll > python312_exports.txt

   :: "ordinal hint RVA name" başlığının altındaki, dört sütunlu (ordinal/hint/RVA/name) satırları
   :: ayıklayıp isim sütununu al -- python312_exports.txt'nin başındaki/sonundaki dumpbin banner ve
   :: "Summary" bölümü dört sütunlu DEĞİL, bu yüzden satır şekline göre filtrelemek (awk ile
   :: "$1 sayısal, $2/$3 hex, NF==4" testi) yeterli; sadece son sütunu "$4" almak banner
   :: satırlarındaki rastgele son kelimeleri de (Dumper, functions, name, ...) yanlışlıkla
   :: sembolmüş gibi işlemeye sokuyor -- bu tuzağa 2026-09-21'de gerçekten düşüldü, ilk üretilen
   :: .def'te 6 sahte satır vardı (1712 satır, olması gereken 1706), ikinci denemede düzeltildi.

   echo LIBRARY python312 > python312.def
   echo EXPORTS >> python312.def
   awk "$1 ~ /^[0-9]+$/ && $2 ~ /^[0-9A-Fa-f]+$/ && $3 ~ /^[0-9A-Fa-f]{8}$/ && NF==4 {print $4}" python312_exports.txt >> python312.def

   lib /def:python312.def /out:python312.lib /machine:x64
   ```

   Sonuç: 1706 export (CPython 3.12.10'un `python312.dll`'inin export sayısıyla birebir eşleşiyor)
   içeren, MSVC `link.exe`'nin doğrudan okuyabildiği gerçek bir import lib. `python312.lib` daha
   sonra `3rdParty/scripts/python312/libs/` altına kopyalandı.

## Neden bu üç parçalı yöntem

Görevin kendisi "tam bir Windows installer kurmadan header/import-lib nasıl elde edilir" sorusunu
araştırmayı istedi. NuGet paketi (`python` / `pythonx64` paketleri hem header hem import lib
içeriyor) kullanıcının bu oturumda **elle vendoring'i NuGet'e tercih ettiği** açıkça belirtildiği
için bilerek kullanılmadı — `AppBuilder.vcxproj`'a hiçbir `<PackageReference>` eklenmedi, sadece
düz include/lib path'leri. `dumpbin`+`lib.exe` yöntemi zaten bu repo'da libgcrypt için daha önce
kanıtlanmış, aynı iki araca (MSVC toolchain'in kendi parçaları, ekstra bağımlılık yok) ihtiyaç
duyan bir yöntem olduğu için tekrarlandı.

## Yeniden kurulum adımları (özet)

1. pybind11 zip'ini indirip aç, `include/pybind11` -> `3rdParty/scripts/pybind11310/include/pybind11`.
2. Embeddable zip'i indirip aç, tüm içeriği -> `3rdParty/scripts/python312/bin/`.
3. Kaynak tarball'ını indirip `Include/` ve `PC/pyconfig.h`'ı aç -> `3rdParty/scripts/python312/Include/`
   (pyconfig.h, `Include/pyconfig.h` olarak).
4. `bin/python312.dll` üzerinde yukarıdaki `dumpbin`+`lib.exe` adımlarını çalıştır ->
   `3rdParty/scripts/python312/libs/python312.lib`.

## Doğrulama

Değişiklikten sonra en az şunu derleyip çalıştırın:

```bat
msbuild projects\msvc\AppBuilder\AppBuilder.vcxproj /p:Configuration=Release /p:Platform=x64
```

Çıktı klasöründe `python312.zip`, `python312.dll` ve `*.pyd` dosyalarının `AppBuilder.exe` ile aynı
klasöre kopyalandığını, ve `RunPythonScript*Test` metotlarının (10 tanesi) hepsinin `PASSED`
yazdığını doğrulayın.
