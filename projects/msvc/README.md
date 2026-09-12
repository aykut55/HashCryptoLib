# CryptoAPI Visual Studio proje iskeletleri

Visual Studio 2022 veya üzerindeki bir sürümde `All/All.sln` açılır. Altı proje
ayrı ayrı kendi `.sln` dosyalarıyla da açılabilir. Bunlar CryptoAPI'nin
Microsoft Visual C++ proje iskeletleridir; SDK implementasyonu henüz
eklenmemiştir.

| Proje | Tür | Planlanan görev |
| --- | --- | --- |
| AppBuilder | Console EXE | Asıl CLI uygulaması |
| AppRunner | Console EXE | CLI'ı ayrı süreçte çalıştıran test/örnek host |
| DllBuilder | Native DLL | SDK'nın DLL dağıtımı |
| DllRunner | Console EXE | DLL'i çalışma zamanında yükleyen API ve ABI doğrulama uygulaması |
| LibBuilder | Static library | SDK'nın statik LIB dağıtımı |
| LibRunner | Console EXE | Statik SDK kullanım ve uyumluluk uygulaması |

`AppRunner`, `DllRunner` ve `LibRunner` şu anda yalnız Visual Studio'nun ürettiği
örnek giriş noktalarını içerir. `DllBuilder` örnek export'lara, `LibBuilder` ise
örnek bir kütüphane fonksiyonuna sahiptir. Ortak SDK kodu, C ABI export katmanı
ve projeler arasındaki bağlantılar henüz eklenmemiştir.

## Ortak kaynaklar ve yapılandırmalar

Ortak üretim kodları depo kökündeki `src` klasöründe tutulacaktır. Proje başına
göreli kaynak yolu `../../../src`, public include yolu ise
`../../../src/include` olacaktır. SDK kaynakları ilgili projelere dosya
referanslarıyla eklenecek, proje klasörlerine kopyalanmayacaktır.

Projelerde aşağıdaki yapılandırmalar tanımlıdır:

- `Debug|x86`
- `Release|x86`
- `Debug|x64`
- `Release|x64`

Projeler Visual Studio 2022 `v143` platform araç takımını ve Windows SDK 10.0'ı
hedefler. Çıktı ve ara derleme dosyalarının konumları MSBuild/Visual Studio proje
ayarlarına göre belirlenir ve kök `.gitignore` kurallarıyla sürüm kontrolünün
dışında tutulur.

## Derleme

Visual Studio Developer PowerShell veya Developer Command Prompt içinde:

```bat
msbuild All\All.sln /m /t:Build /p:Configuration=Debug /p:Platform=x86
msbuild All\All.sln /m /t:Build /p:Configuration=Release /p:Platform=x64
```

Tek bir proje, kendi solution dosyası açılarak veya doğrudan ilgili `.vcxproj`
dosyası MSBuild'e verilerek de derlenebilir.

## Mevcut durum

Altı proje `All/All.sln` içinde birlikte tanımlanmıştır. Proje türleri ve
x86/x64, Debug/Release eşlemeleri hazırdır. Mevcut kaynaklar Visual Studio'nun
başlangıç şablonlarıdır; kriptografi, sertifika, TLS, SSH, runner bağlantıları
ve CLI davranışı henüz uygulanmamıştır.

İlk geliştirme adımında sürümlü C ABI başlıkları `src/include/aycrypto/c`
altında, ortak çekirdek ise `src/core` altında oluşturulacaktır. `DllBuilder` ve
`LibBuilder` aynı ortak kaynaklardan DLL ve gerçek statik LIB üretecek;
runner'lar kriptografi işlemlerini yeniden uygulamayacaktır.
