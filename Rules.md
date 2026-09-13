# Kurallar

## Dosya biçimi

- Her dosya değişikliğinden sonra, değiştirilen dosyanın satır sonları Windows uyumlu CRLF olacak şekilde düzenlenir; karışık LF/CRLF satır sonları bırakılmaz.

## Sınıf ve interface adlandırma

- C++ class adları `C` harfiyle başlar. Örnek: `CCryptoApi`.
- Interface adları `I` harfiyle başlar. Örnek: `ICryptoProvider`.
- Dosya adlarında class ve interface önekleri kullanılmaz. Örnek: `CCryptoApiTester` sınıfı `CryptoApiTester.h` ve `CryptoApiTester.cpp` dosyalarında tutulur.

## Metot adlandırma

- Parametresiz metotların bildirim ve tanımlarında boş `()` yerine `(void)` kullanılır. Örnek: `const char* GetVersion(void) const;`.
- Aksi belirtilmedikçe metin döndürmek için tasarlanan metotlar `const char*` döndürür.
- Döndürülen `const char*` salt okunurdur ve çağıran taraf bu belleği değiştirmez veya serbest bırakmaz.
- Yazılabilir metin çıktısı gerektiğinde çağıran tarafın sağladığı `char*` buffer ve buffer kapasitesi kullanılır.

- `public` metot adları büyük harfle başlar. Örnek: `CalculateCheckSum`.
- `protected` ve `private` metot adları küçük harfle başlar. Örnek: `calculateCheckSum`.
- Constructor ve destructor adları C++ gereği sınıf adıyla aynıdır.
- Her method implementasyonunun kapanış süslü parantezinden hemen sonra `.cpp` dosyasında toplam 80 karakterlik `// -----------------------------------------------------------------------------` ayıracı eklenir. Ayraçtan sonra sonraki methoddan önce bir boş satır bırakılır.
- `.cpp` dosyalarındaki method tanımlarında (implementasyonlarda) parametre listesi tek satırda yazılır (örnek: `int CCryptoApi::EncryptFile(const char* password, const char* inputFilePath, const char* outputFilePath, ProgressCallback onProgress, void* progressUserData)`). Bu kural yalnız `.cpp` implementasyonu içindir; `.h` dosyasındaki bildirimlerde mevcut çok satırlı/hizalı format korunur.

## Hata ve exception yönetimi

- Yazılan her method implementasyonuna otomatik olarak try/catch blokları eklenir.
- DLL sınırından exception dışarı taşırılmaz; yakalanan hatalar uygun error code değerlerine dönüştürülür.

## Metin ve buffer kodlaması

- EncryptBuffer ve DecryptBuffer ikili veri API’leridir; input/output buffer’ları byte dizisi olarak işlenir ve Unicode/ANSI dönüşümü uygulanmaz.
- Bu metotların const char* password parametresi UTF-8 metin taşır; passwordSize UTF-8 byte uzunluğudur.
- Buffer API’leri için ayrı Unicode veya ANSI overload’ları eklenmez. Metin API’lerinde encoding açıkça belirtilir.

- EncryptString ve DecryptString UTF-8 byte dizileri kullanır; uzunluklar terminatör hariç byte sayısıdır. Çıktı çağıranın bufferına yazılır ve otomatik null terminator eklenmez.
- EncryptFile ve DecryptFile dosya yolları UTF-8 olarak verilir; ANSI code page varsayılmaz.

- Output buffer kapasitesi yetmediğinde metot `BUFFER_TOO_SMALL` döndürür ve `outputBufferSize` içine gereken kapasiteyi yazar. Kapasite sorgusu için `outputBufferCapacity = 0` ve `outputBuffer = nullptr` verilir.

## Yeni class yaratma

- Her sınıf için ayrı `.h` ve `.cpp` dosyaları oluşturulur.
- Header dosyasında sınıfa özgü, benzersiz `#ifndef` / `#define` include guard kullanılır ve dosya `#endif` ile kapatılır.
- Sınıflar `CryptoApiNS` namespace'i içinde tanımlanır.
- Namespace, sınıf ve fonksiyon açılış süslü parantezleri ayrı satıra yazılır.
- Erişim bölümleri sırasıyla `public:`, `protected:` ve `private:` olur. Boş bölümler de korunur.
- `public:` altında önce `virtual` destructor (dtor), ardından constructor (ctor) bildirimi yazılır.
- Constructor adı, destructor adındaki `~` işaretinden sonraki sınıf adıyla aynı sütunda hizalanır.
- Constructor ve destructor gövdeleri `.cpp` dosyasında, aynı namespace içinde ve önce destructor gelecek şekilde tanımlanır. `virtual` yalnız header bildiriminde yazılır.
- Başlangıçta gövdeler boş bırakılır; istenmeden ek metot veya üye eklenmez.
- Namespace kapanışında `// namespace CryptoApiNS` açıklaması kullanılır.

Örnek header düzeni:

```cpp
#ifndef AYCRYPTO_CRYPTO_API_H
#define AYCRYPTO_CRYPTO_API_H

namespace CryptoApiNS
{

class CCryptoApi
{
public:
    virtual ~CCryptoApi();
             CCryptoApi();

protected:

private:

};

} // namespace CryptoApiNS

#endif
```

## Yeni MSVC projesi ekleme veya oluşturma

- Yeni proje `projects/msvc` altında oluşturulur ve `projects/msvc/All/All.sln` çözümüne eklenir.
- Proje dört yapılandırmayı destekler: `Debug|Win32`, `Release|Win32`, `Debug|x64` ve `Release|x64`.
- Her yapılandırmada projeye özel kimlik makrosu tanımlanır. Örnekler: `APP_BUILDER`, `APP_RUNNER`, `DLL_BUILDER`, `DLL_RUNNER`, `LIB_BUILDER`, `LIB_RUNNER`.
- Win32 yapılandırmalarında `ARCH_X86` ve `ARCH_WIN32`; x64 yapılandırmalarında `ARCH_X64` ve `ARCH_WIN64` tanımlanır.
- Debug yapılandırmalarında `BUILD_DEBUG`, Release yapılandırmalarında `BUILD_RELEASE` tanımlanır.
- Her yapılandırmada `MultiProcessorCompilation` varsayılanı `true` olur.
- Proje Visual Studio filtre dosyası kullanıyorsa yeni kaynak ve başlık dosyaları uygun filtrelere eklenir.

Örnek çok işlemcili derleme ayarı:

```xml
<ItemDefinitionGroup>
  <ClCompile>
    <MultiProcessorCompilation>true</MultiProcessorCompilation>
  </ClCompile>
</ItemDefinitionGroup>
```
