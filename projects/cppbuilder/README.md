# CryptoAPI C++Builder proje iskeletleri

C++Builder IDE'de `All/All.groupproj` açılır. Altı proje ayrı ayrı kendi
`.cbproj` dosyalarıyla da açılabilir. Bunlar Visual Studio projelerinin
C++Builder karşılıklarıdır; SDK implementasyonu henüz eklenmemiştir.

| Proje | Tür | Planlanan görev |
| --- | --- | --- |
| AppBuilder | Console EXE | Asıl CLI uygulaması |
| AppRunner | Console EXE | CLI'ı ayrı süreçte çalıştıran test/örnek host |
| DllBuilder | Native DLL | SDK'nın DLL dağıtımı |
| DllRunner | Console EXE | DLL yükleme ve API kullanım örneği |
| LibBuilder | Static library | SDK'nın statik dağıtımı |
| LibRunner | Console EXE | Statik SDK kullanım örneği |

AppRunner görevi mimari öneridir; şu an bütün runner'lar yalnız boş giriş
noktası içerir. DLL export API'si ve projeler arası bağlantılar henüz eklenmez.
LibBuilder tek bir boş placeholder fonksiyon içerir.

## Ortak kaynak ve çıktılar

Ortak kodlar kökteki `src` klasöründedir. Proje başına göreli yol
`../../../src`, public include yolu `../../../src/include` olarak hazırdır.
SDK kaynakları yazıldığında ilgili projelere dosya referanslarıyla eklenir;
projeler arasında kopyalanmaz.

Win32 (classic BCC32) ve Win64 (BCC64), Debug/Release tanımlıdır.
VCL/FMX veya runtime package bağımlılığı yoktur. Çıktılar her projenin
`build/<Platform>/<Config>` dizinindedir. Win64 statik kütüphane uzantısı
toolchain tarafından belirlenir; MSVC LIB ile ikili uyumluluk varsayılmaz.

## Derleme

Kurulu C++Builder'ın RAD Studio Command Prompt ortamında:

```bat
msbuild All\All.groupproj /t:Build /p:Config=Debug /p:Platform=Win32
msbuild All\All.groupproj /t:Build /p:Config=Release /p:Platform=Win64
```

`BDS` ortam değişkeni ve `CodeGear.Cpp.Targets` kurulu C++Builder'dan alınır;
makineye özel kurulum yolu proje dosyalarına yazılmaz. Eski IDE projeyi
kaydettiğinde veya yeni IDE yükselttiğinde proje sürümü metadata'sı değişebilir.
C++Builder 10+ hedeflenir; her sürümün doğrulanması ayrı derleme gerektirir.

## Yapılan doğrulama

10 Eylül 2026: Kurulu RAD Studio 37.0 araçlarıyla altı projenin tamamı
Win32/Win64 ve Debug/Release kombinasyonlarında başarıyla derlendi (24 hedef).
C++Builder 10 üzerinde henüz test yapılmadı. IDE arayüzünde açma/kaydetme
kontrolü yapılmadı; doğrulama yerel MSBuild/CodeGear araçlarıyla gerçekleştirildi.

Yerel kurulumun `include/windows/sdk` dizininde `windows.h` bulunmadığı görüldü.
Boş DLL giriş noktası bu başlığa ihtiyaç duymadan derlenir. Windows API'lerini
kullanan gerçek SDK kodlarına geçerken C++Builder Windows SDK başlıklarının
kurulumu ayrıca tamamlanmalı/doğrulanmalıdır.
