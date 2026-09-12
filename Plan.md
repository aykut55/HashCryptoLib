# CryptoAPI — C++ SDK Mimari ve Uygulama Planı

Tarih: 10 Eylül 2026  
Durum: Tasarım taslağı; uygulama kodlaması başlamadı.  
Dosya adı: `plan.md`.  
SDK/proje adı kullanıcı kararıyla `CryptoAPI` olarak belirlenmiştir. C++ namespace'i önceki önerideki `aycrypto`, facade sınıfı `CryptoApi`, tam sınıf adı `aycrypto::CryptoApi` olacaktır. Örneklerde `sdk` yalnız nesne değişkeninin adıdır. Microsoft'un API ailesi belgelerde `Microsoft CryptoAPI (CAPI)` olarak anılacaktır.

C++ namespace'i sınıf ve fonksiyon isimlerini ayırır; C export'ları ve dosya adlarını kapsamaz. Bu nedenle dış C ABI fonksiyonları/tipleri `aycrypto_` öneki kullanacak, DLL/static/import dosyaları aşağıdaki açık adlarla paketlenecektir. Public başlıklarda global `using namespace` bildirimi bulunmayacaktır.

## 1. Amaç ve kapsam

Microsoft Visual Studio ve Borland/Embarcadero C++Builder uygulamalarından kullanılabilen, sınıf tabanlı, genişletilebilir bir C++ SDK geliştirilecek. İlk sağlayıcı Windows kriptografi API'lerini kullanacak. Sonraki sağlayıcılar Crypto++, Botan, OpenSSL ve kendi C++ implementasyonlarımız olacak. OpenPGP desteği ayrıca bir mesaj/protokol modülü olarak eklenecek.

Ana servisler kendi sınıflarına sahip olacak:

| İşlev | Servis sınıfı | Temel sorumluluk |
| --- | --- | --- |
| Encryption | `Encryptor` | Simetrik ve hibrit şifreleme |
| Decryption | `Decryptor` | Bütünlük doğrulamasıyla şifre çözme |
| Hashing | `Hasher` | Tek seferlik ve artımlı özet hesaplama |
| Signing | `Signer` | Özel anahtarla dijital imza |
| Verification | `Verifier` | İmza ve ayrı bütünlük doğrulama işlemleri |
| RandomNumber Generation | `RandomGenerator` | Kriptografik rastgele byte ve sayı üretimi |
| Certificates | `CertificateManager` | X.509 sertifikaları, depolar, CSR ve güven doğrulaması |
| SSL / TLS | `TlsService` | TLS istemci/sunucu oturumları ve güvenli veri akışı |
| SSH | `SshService` | SSH2 bağlantısı, kimlik doğrulama, kanallar ve SFTP |

Bu servisler bağımsız kullanılabilecek; `aycrypto::CryptoApi` facade sınıfı aynı servisleri tek giriş noktasında toplayacak. Yardımcı servisler: `KeyManager`, `KeyDeriver`, `MacService`, `BatchProcessor`, `ManifestService`, `ProviderRegistry`, `ScriptEngine`. Public C++ sınıfları `aycrypto` namespace'i altında yer alacak.

Girdi/çıktı kapsamı: byte tamponları, string/strings, file/files, folder/folders, stream/streams. Generiklik, farklı veri kaynaklarının ve sağlayıcıların aynı işleme bağlanabilmesi anlamına gelecek. Template desteği bunun C++ istemci tarafındaki kolaylaştırıcı katmanı olacak.

Kullanıcının eklediği zorunlu kullanım ve dağıtım biçimleri: doğrudan C++ sınıfları, DLL, DLL Runner, statik LIB, LIB Runner ve bağımsız EXE. Runner burada ilgili kütüphaneyi kullanan çalıştırıcı/örnek/test uygulaması olarak yorumlanmıştır; aşağıda her birinin bağlantı biçimi açık tanımlanır.

İlk sürüm Windows masaüstü ve servis uygulamalarını hedefler. X.509 sertifika yönetimi ve politika tabanlı zincir doğrulaması Certificates kapsamına dahildir. SSL/TLS ve SSH ayrı protokol servisleri olarak yol haritasına eklenmiştir. Linux/macOS, PDF/XML imzası, Authenticode, nitelikli elektronik imza, tam CA işletimi ve uzun dönem imza doğrulaması ayrı genişleme konularıdır; sırf bir imza algoritması veya sertifika desteği bulunduğu için desteklenmiş sayılmaz.

## 2. Platform ve derleyici uyumluluğu

### 2.1 Kullanıcının bildirdiği sınırlar

- Borland/Embarcadero C++Builder 10 ve üzeri kesin hedeftir.
- Microsoft Visual Studio 2022 ve üzeri kesin derleyici hedefidir; kullanıcı önceki “Windows 2022” ifadesini bu şekilde netleştirmiştir.
- Çalışma ortamı şimdilik Windows'tur. Windows Server 2022 zorunluluğu yoktur. Minimum Windows sürümü ayrıca seçilecek; mevcut gereksinim bütün tarihsel Windows sürümlerine destek anlamına gelmez. İşletim sistemine bağlı TLS gibi yetenekler çalışma zamanında sorgulanır.
- Win32 ve Win64 ayrı paketler olarak tasarlanır. Win32 uygulama yalnız x86 DLL, Win64 uygulama yalnız x64 DLL yükler.
- Gelecek IDE sürümleri otomatik olarak sertifikalı sayılmaz; destek tablosuna testten sonra eklenir.

### 2.2 Uyumluluğun üç farklı anlamı

1. Kaynak uyumluluğu: SDK başlıklarının hedef derleyicide derlenmesi.
2. İkili uyumluluk: istemcinin SDK DLL'ini güvenle çağırması; bellek, exception ve çağrı sözleşmesinin aynı olması.
3. Davranış/veri uyumluluğu: aynı algoritma ve formatın IDE ve sağlayıcı değiştiğinde aynı şekilde yorumlanması.

“Full compatible” kabul kriteri bu üç düzeyin belirlenen sürüm/mimari matrisinde doğrulanmasıdır. Farklı derleyicilerin aynı C++ `.lib`, STL veya sınıf ikili gösterimini paylaşacağı varsayılmaz. Embarcadero da derleyici aileleri arasında ABI farklarını belgeliyor. [C++ derleyicileri](https://docwiki.embarcadero.com/RADStudio/Athens/en/C%2B%2B_Compilers)

### 2.3 Önerilen uyumluluk çözümü

| Katman | Teknoloji | Dağıtım ve sorumluluk |
| --- | --- | --- |
| Ortak SDK çekirdeği | Classic BCC32'de doğrulanacak muhafazakâr C++03 alt kümesi | Aynı kaynaklardan toolchain'e özel statik LIB ve DLL üretimi |
| Ortak dış sınır | Sürümlü C ABI | Bütün istemcilerin kullandığı fonksiyonlar ve opaque handle'lar |
| Ortak C++ wrapper | Muhafazakâr C++03 alt kümesi | C++Builder 10 classic dahil hedeflerde derlenen RAII sınıfları ve basit template'ler |
| Modern C++ wrapper | C++11/17 özelliklerine göre seçilen başlıklar | Lambda, move, `std::function`, uygun hedefte `std::future` vb. |
| VCL adaptörü | İlgili C++Builder sürümü | `UnicodeString`, `TStream`, VCL olayları |
| Sağlayıcı modülleri | Her bağımlılığın gerektirdiği derleyici | Çekirdeğe C ABI ile bağlı opsiyonel DLL'ler |

Classic BCC32 ile Clang tabanlı derleyicilerin modern C++ özellikleri aynı değildir; IDE sürümü tek başına özellik garantisi sayılmaz. Ortak wrapper'a `nullptr`, `noexcept`, variadic template veya concepts zorunluluğu konmaz. [Embarcadero modern C++ özellikleri](https://docwiki.embarcadero.com/RADStudio/Athens/en/Modern_C%2B%2B_Features_Supported_by_RAD_Studio_Clang-enhanced_C%2B%2B_Compilers)

Botan gibi C++20 gerektiren bir sağlayıcı kendi modülünde derlenebilir; bu gereksinim Borland istemciye taşınmaz. Bu, Botan belgelerindeki dil gereksiniminden hareketle seçilen mimari çözümdür. [Botan derleme belgesi](https://botan.randombit.net/handbook/building.html)

Statik LIB ve DLL dağıtımı birlikte zorunludur. Statik LIB, her desteklenen toolchain/CRT için ayrı üretilir ve gerçekten çekirdek uygulamasını içerir. DLL import library'si statik SDK olarak sunulmaz. C++Builder tarafında DLL için uygun import library araçları kullanılır; DLL Runner ayrıca sabit isimli export'ları `LoadLibraryExW`/`GetProcAddress` üzerinden yükler. İki bağlantı yöntemi de test edilir.

Gerçek statik LIB gereksinimi nedeniyle ortak çekirdeği yalnız MSVC C++17 ile derleme yaklaşımı kullanılmayacak. Ortak kaynaklar C++03 uyumlu alt kümeye indirgenecek; thread, mutex, atomik sayaç, dosya ve platform özellikleri iç Windows adaptörleriyle sağlanacak. Modern wrapper C++11/17 kolaylıklarını koruyacak. Böylece classic BCC32 statik paketi bir MSVC DLL'ine gizli biçimde bağımlı olmayacak. Bunun maliyeti daha kısıtlı iç dil kullanımı ve daha geniş derleyici testidir.

Modern harici sağlayıcıların classic BCC32 ile statik derlenmesi ayrıca kanıtlanmadan vaat edilmez. İlk sürümde bütün hedefler için gerçek statik çekirdek + Windows CNG hedeflenir. Botan gibi modern motorlar bu istemcilerde provider DLL olarak kullanılabilir; böyle bir paket açıkça “statik çekirdek + dinamik sağlayıcı” diye etiketlenir. Tam statik üçüncü taraf paketleri yalnız bağımlılığın desteklediği ve test edilen toolchain kombinasyonlarında sunulur.

### 2.4 Destek matrisi ve ilk teknik doğrulama

| Hedef | Mimari | Wrapper | Kabul durumu |
| --- | --- | --- | --- |
| Visual Studio 2022 ve seçilen sonraki sürümler | x86/x64 | Ortak ve modern | Kullanıcı gereksinimi; sürüm/toolset bazında test edilecek |
| C++Builder 10.0–10.4 classic BCC32 bulunan kurulumlar | x86 | Ortak | Her erişilebilir sürümde derleme ve çalışma testi |
| C++Builder 10.x Clang tabanlı hedefler | Kurulumun sunduğu x86/x64 | Ortak; desteklediği modern özellikler | Derleyici bazında test |
| C++Builder 11 ve üzeri | Sürümün sunduğu x86/x64 | Ortak ve uygun modern wrapper | Seçilen sürüm/güncelleme bazında test |

Faz 0'da yalnız uyumluluk prototipi yapılır: DLL yükleme, sürüm sorgusu, buffer tahsisi/serbest bırakma, 64-bit boyut, callback, UTF-8 yol ve bir hash çağrısı. Bu prototip tasarım tamamlandıktan sonra yazılır. Kurulu olmayan ticari IDE sürümlerine “test edildi” denmez; uygun test makinesi sağlanınca doğrulanır.

## 3. Genel mimari

```text
Visual Studio uygulaması           C++Builder / VCL uygulaması
         |                                   |
 C++ sınıfları + templates           C++ sınıfları + VCL adaptörü
         +-----------------+-----------------+
                           |
                 Sürümlü ve sabit C ABI
                           |
                aycrypto::CryptoApi facade
                           |
 Encryptor | Decryptor | Hasher | Signer | Verifier | RandomGenerator
                           |
 Policy + KeyManager + CertificateManager + OperationContext + I/O + Batch + EventDispatcher
                           |
          ProviderRegistry / yetenek ve anahtar uyumu seçimi
                           |
 Windows CNG | Crypto++ | Botan | OpenSSL | CustomProvider

 Opsiyonel: Lua -> aynı servis API'si
 Opsiyonel: OpenPgpService -> OpenPgpProvider -> RNP veya GPGME/GnuPG
 Protokol: TlsService -> ITlsProvider -> Windows Schannel veya OpenSSL libssl
 Protokol: SshService -> ISshProvider -> libssh2; sunucu genişlemesinde libssh adayı
 Ortak ağ: NetworkTransport + OperationContext + EventDispatcher
```

Bağımlılık yönü üstten alta olur. Çekirdek VCL, UI, Lua veya belirli bir üçüncü taraf başlığına bağımlı olmaz. Windows sağlayıcısı ilk paketle gelir; diğer sağlayıcılar kurulmadığında temel SDK çalışmaya devam eder.

### 3.1 Katmanların sorumlulukları

- Public API: adlar, parametreler, veri sahipliği, sonuçlar, capability sorguları.
- Application services: işi koordine eder; politika, anahtar, I/O ve sağlayıcıyı birleştirir.
- Domain/contracts: algoritma tanımları, key descriptor, hata kodları, işlem durumları.
- I/O: kaynakları byte akışına dönüştürür, kısa okuma/yazma ve commit yönetir.
- Providers: yalnız desteklediği kriptografik işlemleri gerçekleştirir.
- Formats: envelope, manifest, signature package ve OpenPGP gibi serileştirmeler.
- Integrations: VCL, modern STL, Lua ve uygulama dispatcher adaptörleri.

## 4. Design Patterns ve uygulanacağı yerler

| Pattern/ilke | Uygulama | Gerekçe |
| --- | --- | --- |
| Facade | `aycrypto::CryptoApi` | Servislere tek erişim noktası |
| Strategy | `IAeadCipher`, `IHashSession`, `ISignatureEngine`, `IRandomSource` | Aynı işlemde sağlayıcı değiştirme |
| Abstract Factory | `ICryptoProvider` | Uyumlu oturum ve anahtar nesneleri oluşturma |
| Adapter | CNG/OpenSSL/Botan/Crypto++, STL/VCL I/O | Dış API'leri ortak sözleşmeye uyarlama |
| Bridge | Servis API'si ile sağlayıcı sözleşmesinin ayrılması | Veri kaynağı ve kripto motorunun bağımsız gelişmesi |
| Observer | `IEventSink`, event abonelikleri | İlerleme ve durum bildirimi |
| Command | `OperationRequest`, `OperationHandle` | Senkron/asenkron yürütme, iptal ve batch |
| Composite | `BatchRequest`, klasörden oluşturulan dosya işleri | Tekil ve toplu işleri ortak yürütücüyle işleme |
| Decorator | Counting, bounded, staging stream adaptörleri | Sayaç, limit ve commit davranışını kripto kodundan ayırma |
| Builder | `SdkOptionsBuilder`, `EncryptionOptionsBuilder` | Çok parametreli kurulumda erken doğrulama |
| RAII | Anahtarlar, context'ler, buffer'lar, dosyalar | Kaynakların bütün çıkış yollarında bırakılması |
| PImpl / opaque handle | C++ wrapper ve C ABI | Uygulama ayrıntılarını ve ABI değişimini sınırlandırma |
| Dependency Injection | Registry, RNG, dispatcher, storage bağlama | Test edilebilirlik ve uygulamaya göre kurulum |

Global Singleton kullanılmayacak; aynı süreçte farklı politikalarla birden fazla SDK instance'ı oluşturulabilecek. Kalıtım küçük arayüzlerle sınırlanacak, davranış birleştirme çoğunlukla composition ile yapılacak. Pattern kullanımı gerçek bir değişim noktasına hizmet edecek.

## 5. API ve sınıf sözleşmeleri

### 5.1 Ana sınıflar

| Sınıf | Tasarlanan işlemler | Yaşam döngüsü |
| --- | --- | --- |
| `aycrypto::CryptoApi` | `encryptor`, `decryptor`, `hasher`, `signer`, `verifier`, `random`, `certificates`, `tls`, `ssh`, `keys`, `batch` | Paylaşılan servis ve registry sahibi |
| `Encryptor` / `Decryptor` | `process`, `start`, `createSession` | Her çağrı ayrı işlem context'i |
| `Hasher` | `compute`, `createSession`, `computeMany` | Session başına ayrı hash durumu |
| `Signer` | `signMessage`, `signDigest`, `signManifest` | Anahtar ve algoritma profiliyle işlem |
| `Verifier` | `verifyMessage`, `verifyDigest`, `verifyManifest`, `compareDigest` | Doğrulama raporu döndürür |
| `RandomGenerator` | `fill`, `generateBytes`, `uniformInteger`, `generateTo` | Sağlayıcı RNG hizmeti |
| `KeyManager` | `generate`, `import`, `export`, `open`, `describe`, `destroy` | Anahtar politikası ve sağlayıcı bağı |
| `CertificateManager` | `load`, `inspect`, `import`, `export`, `find`, `createSelfSigned`, `createRequest`, `validate` | Sertifika/depo/zincir servislerini koordine eder; bölüm 25 |
| `TlsService` | `createClient`, `createServer`, `capabilities` | TLS context ve bağlantı politikaları; bölüm 26 |
| `SshService` | `createClient`, `capabilities` | SSH2 istemci session ve kanal servisleri; bölüm 27 |
| `KeyDeriver` | `deriveFromPassword`, `deriveSubkey` | Parola KDF ve anahtar KDF ayrımı |
| `MacService` | `computeMac`, `verifyMac` | HMAC işlemleri |
| `BatchProcessor` | `submit`, `execute`, `cancel` | Sınırlı eşzamanlılık ve öğe sonuçları |

Servisler `SdkContext` ile bağımsız oluşturulabilecek; facade zorunlu olmayacak. Facade servisleri sahiplenir, sağlayıcılar ve anahtarlar aktif işlemler bitene kadar hayatta tutulur. Context kapatma yeni işleri reddeder ve aktif işlerin kapatma politikasını uygular.

### 5.2 Temel veri tipleri

- `ByteView`: salt okunur pointer + uzunluk; sahiplik almaz.
- `MutableByteView`: yazılabilir pointer + kapasite.
- `ByteBuffer`: sahipli genel veri; çıktı boyutu açıkça bilinir.
- `SecureBuffer`: anahtar/parola için kontrollü tahsis; örtük kopya yok, bırakılırken silme.
- `TextView`: açık encoding ile metin; raw ciphertext taşımaz.
- `KeyHandle`: anahtarın opaque referansı; ham anahtar gibi serileştirilemez.
- `AlgorithmDescriptor`: algoritma, mod, key size, tag size, digest, padding, signature encoding.
- `OperationOptions`: politika, sağlayıcı seçimi, limitler, cancellation ve observer.
- `OperationResult`: durum, işlenen byte, çıktı bilgisi, gerçekten kullanılan sağlayıcı ve uyarılar.
- `VerificationResult`: `Valid`, `Invalid`, `Indeterminate` sonucu; teknik hata ayrı durum kodudur.
- `BatchResult`: bütün öğe sonuçları ve `Succeeded`, `PartialSuccess`, `Failed`, `Cancelled` özeti.

### 5.3 C ABI kuralları

1. `extern "C"` export'lar, açık çağrı kuralı; Windows için `__cdecl` hedeflenir. Callback typedef'leri de aynı kurala sahip olur.
2. Sınıf, STL nesnesi, C++ exception, RTTI, `FILE*` veya `std::stream` DLL sınırından geçirilmez.
3. Sabit genişlikli tamsayılar kullanılır; C++Builder için typedef uyumluluk başlığı sağlanır. ABI'de `bool`, `long` ve derleyiciye bağlı enum boyutu kullanılmaz.
4. File/stream toplam uzunlukları 64 bit; tek çağrı buffer uzunlukları tanımlı sınırlarla çalışır. Büyük veriler chunk'lara bölünür.
5. Yapılar `struct_size`, `abi_version`, ayrılmış alanlar içerir. Hizalama açık tanımlanır ve her toolchain'de `sizeof`/`offsetof` doğrulanır. Yapılar dosyaya doğrudan yazılmaz.
6. C API pointer ve uzunluk alır. Sıfır uzunlukta null pointer geçerliliği fonksiyon bazında belgelenir; metinler length-aware olur.
7. Belleği tahsis eden modül serbest bırakır. DLL çıktısı yalnız `aycrypto_buffer_free`; istemci `delete`/`free` kullanamaz. Alternatif caller-owned buffer API'si bulunur.
8. Kaynak ve callback yaşam süreleri belgelenir. Asenkron çağrı, geçici stack buffer'ını örtük olarak saklamaz; sahiplik devri/kopya/açık retain seçenekleri gerekir.
9. Hatalar sabit durum kodu ve güvenli hata ayrıntısıyla döner. Wrapper isterse kendi derleyicisinde exception'a çevirir.
10. İsim dekorasyonu ve export listesi `.def` ile sabitlenir. C++ wrapper kendi istemci CRT'sinde çalışır.
11. `aycrypto_get_api` ana ABI sürümü ve fonksiyon tablosu kapasitesini doğrular; eksik opsiyonel fonksiyonlar capability olarak görünür.
12. Handle serbest bırakma, invalid handle, çift kapatma ve kapanış sırası sözleşmesi test edilir; süreçler/mimariler arasında handle taşınmaz.

### 5.4 Generic ve template yaklaşımı

Kriptografik işleme giren ortak birim byte akışıdır. Template'ler dosya yolu, metin, container ve stream'i uygun adaptöre bağlar; kriptografik algoritmalar her veri tipi için tekrar yazılmaz.

Tasarlanan aileler: `BasicSource<T, Traits>`, `BasicSink<T, Traits>`, `Batch<TItem>`, `Result<T>`. Modern katmanda iterator/range kolaylıkları eklenebilir. Ortak katmanda basit template ve traits specialization kullanılır; kısmi uzmanlaşma gibi özellikler en eski hedef derleyicide kontrol edilir.

Önemli sınırlar:

- `std::string` bir dosya yolu da metin de olabileceğinden örtük tahmin yapılmaz: `FileSource(path)` ve `TextSource(text, encoding)` ayrıdır.
- `UnicodeString` UTF-8'e açık kuralla dönüştürülür. `AnsiString` için code page belirtilir; sistem varsayılanına sessiz bağımlılık kurulmaz.
- Byte container kabulünde eleman türü ve erişim biçimi doğrulanır. Her `T` nesnesinin belleğini `sizeof(T)` ile şifreleyen genel API bulunmaz.
- Uygulama nesneleri için açık `Serializer<T>` gerekir; padding, pointer, endian ve sürüm bağımlılığı taşıyan ham nesne belleği taşınabilir veri sayılmaz.
- Template ve VCL nesneleri istemci içinde kalır; DLL'e pointer/length veya C callback tablosu gönderilir.

### 5.5 Kullanım biçimi taslağı

Aşağıdaki akışlar nihai C++ imzası veya çalışan kod değildir; API'nin kullanıcı açısından okunurluğunu gösterir.

```text
sdk = aycrypto::CryptoApi(options: WindowsCng + DefaultSecurityPolicy)
key = sdk.keys.generate(AES-256, usage: Encrypt|Decrypt)
sdk.encryptor.process(FileSource("girdi.bin"), FileSink("girdi.enc"), key, options)
sdk.decryptor.process(FileSource("girdi.enc"), FileSink("cozulmus.bin"), key, options)
digest = sdk.hasher.compute(TextSource("Merhaba", UTF8), SHA-256)
signature = sdk.signer.signMessage(StreamSource(stream), privateKey, RSA-PSS-SHA256)
result = sdk.verifier.verifyMessage(StreamSource(stream), signature, publicKey)
sdk.random.fill(MutableByteView(buffer, 32))
job = sdk.batch.submit(Files(...), operation: Encrypt, callbacks: observer)
```

String şifreleme sonucu `EncryptedEnvelope` veya `ByteBuffer`; Base64 gösterimi ayrı codec çağrısıdır. Hash sonucu byte ve isteğe bağlı hex/base64 sunulur. Encoding şifreleme algoritması olarak adlandırılmaz.

## 6. Sağlayıcı mimarisi ve seçim

### 6.1 Sözleşmeler

`ICryptoProvider` kimlik, sürüm, çalışma durumu ve yetenek sorgusu sağlar. İşlevler küçük arayüzlere ayrılır: `IAeadCipher`, `IHashSession`, `IMacSession`, `ISignatureEngine`, `IRandomSource`, `IKeyStore`, `IKeyDerivation`.

Provider plugin DLL sınırında C++ virtual interface paylaşılmaz. Bu adlar çekirdek içi kavramsal arayüzlerdir; plugin sınırında sürümlü C fonksiyon tablosu ve opaque context kullanılır.

Capability yalnız “AES var” değildir: algoritma + mod + key length + tag length + streaming biçimi + key import/export + donanım + signature encoding + KDF parametre limitleri birlikte bildirilir. Derleme zamanı desteği, çalışma zamanı erişimi ve politika izni ayrı alanlardır.

### 6.2 Seçim kuralları

1. İstenen algoritma/format/politika doğrulanır.
2. Anahtarın sağlayıcısı, kullanım amacı ve export izni kontrol edilir.
3. İstekle uyumlu yetenek sunan sağlayıcılar bulunur.
4. Açık sağlayıcı tercihi varsa ona uyulur; yoksa instance politikasındaki sıra kullanılır.
5. İşlem başlamadan seçilen sağlayıcı sabitlenir ve sonuçta raporlanır.

Oturum ortasında motor değiştirilmez. Kimlik doğrulama hatası, yanlış anahtar veya RNG hatası başka sağlayıcıyla sessizce yeniden denenmez. Anahtar sağlayıcıya bağlıysa export edilemeden başka motora taşınamaz; “ortak API” anahtarın her yerde taşınabilir olduğu anlamına gelmez.

### 6.3 Planlanan sağlayıcı ve üçüncü taraf desteği

Henüz implementasyon yoktur; tablo destek yol haritasıdır. Sürüm pinleme ve dağıtım dosyalarındaki lisans incelemesi her entegrasyon fazında yapılır.

| Entegrasyon | Rol | Entegrasyon yaklaşımı | Faz |
| --- | --- | --- | --- |
| Windows CNG / BCrypt | Cipher, hash, MAC, imza, RNG, KDF | İlk yerleşik provider | İlk sürüm |
| Windows NCrypt / KSP | Kalıcı ve export edilemeyen özel anahtarlar | `IKeyStore` ve signing adaptörü | İlk sürümün anahtar fazı |
| Windows Crypt32 / Certificate APIs | X.509, depolar, PFX, zincir ve güven politikası | `ICertificateProvider`, `ICertificateStore`, `ICertificateValidator` | Certificates fazı |
| Windows CertEnroll | PKCS#10 CSR ve sertifika talebi oluşturma | COM ayrıntılarını saklayan `ICertificateRequestProvider` | Certificates oluşturma fazı |
| Windows Schannel / SSPI | TLS protokol motoru | `ITlsProvider`; Winsock transport'tan ayrı | SSL/TLS fazı |
| OpenSSL libssl | Alternatif TLS motoru | `ITlsProvider`; libcrypto provider'ından ayrı | TLS harici sağlayıcı fazı |
| libssh2 | SSH2 istemci, kanal ve SFTP | `ISshProvider`; ayrı opsiyonel bağımlılık | SSH istemci fazı |
| libssh | SSH istemci/sunucu motor adayı | Sunucu gereksinimi için ayrı değerlendirme | SSH genişleme fazı |
| Windows DPAPI | Yerel sır/anahtar koruma | Ayrı `LocalSecretProtector` | Anahtar fazı |
| Crypto++ | Alternatif genel kriptografi | Provider DLL; başlıkları dış API'ye sızmaz | İkinci sağlayıcı dalgası |
| Botan 3 ailesi | Alternatif genel kriptografi | Gereken C++20 toolchain ile ayrı modül | İkinci sağlayıcı dalgası |
| OpenSSL 3 ailesi | Genel kriptografi ve anahtar formatları | `libcrypto` EVP ve provider API üzerinden adaptör | İlk harici sağlayıcı önerisi |
| RNP | OpenPGP mesajları ve anahtarları | `OpenPgpProvider` adayı | OpenPGP fazı |
| GPGME + GnuPG | OpenPGP ve mevcut keyring iş akışları | Engine bağımlılıklarını kapsayan alternatif adaptör | İsteğe bağlı OpenPGP seçeneği |
| Custom C++ | Kendi algoritma implementasyonlarımız | Aynı sözleşme, ayrı deneysel politika | Temel sağlayıcılar sonrası |
| Lua | Script iş akışları | C API üzerinden opsiyonel binding | Script fazı |

OpenSSL adaptörü yüksek seviyeli EVP arabirimini esas alacak; SDK'nın provider kavramıyla OpenSSL'in iç provider kavramı ayrı tutulacak. [OpenSSL crypto belgesi](https://docs.openssl.org/3.0/man7/crypto/)

Crypto++ belgelerinde çeşitli MSVC/C++Builder sürümleri listelenmesi tüm hedef kombinasyonlarda destek garantisi değildir; seçilen sürüm modern toolchain ile ayrı derlenip SDK ABI'sinden sunulacak. [Crypto++ derleyicileri](https://www.cryptopp.com/wiki/Compilers)

RNP'nin OpenPGP kütüphanesi olması onu aday yapar; desteklediği RFC özellikleri pinlenen sürümde ayrıca doğrulanır. GPGME, GnuPG engine'ini kullanır ve LGPL kapsamında sunulur; engine'in dağıtımı ve lisansı ayrı kontrol edilir. [RNP projesi](https://github.com/rnpgp/rnp), [GPGME özellikleri](https://gnupg.org/documentation/manuals/gpgme/Features.html)

## 7. Encryption/Decryption

### 7.1 İlk algoritma profili

| Profil | Karar | Kullanım |
| --- | --- | --- |
| AES-256-GCM | Varsayılan | Genel byte/string/file şifreleme |
| AES-128-GCM | Açık seçim | Belirli birlikte çalışabilirlik profilleri |
| AES-GCM nonce/tag | 96-bit nonce, 128-bit tag başlangıç profili | Parametreler formatta açık kaydedilir |
| RSA-OAEP SHA-256 | Küçük veri anahtarını sarmalama | Hibrit şifreleme; büyük dosyayı doğrudan RSA ile işleme yok |
| Parola tabanlı | PBKDF2-HMAC-SHA256 + rastgele salt + AEAD | Paroladan anahtar türetme |
| CBC, ECB, DES, 3DES, RC4 | Yeni veri üretim varsayılanına dahil değil | Somut eski format ihtiyacında ayrı legacy politika |

Windows ilk sağlayıcısında BCrypt cipher işlemleri, NCrypt anahtar saklama işlemleri kullanılır. DPAPI genel, sağlayıcılar arası taşınabilir dosya şifrelemesinden ayrı tutulur. [Microsoft CNG genel bakış](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)

### 7.2 Akış ve oturum

`EncryptSession`/`DecryptSession`: oluşturma → AAD → update → finalize → kaynak bırakma. AAD veri başlamadan sabitlenir. Finalize sonrası update reddedilir. Padding/tag/nonce ayrıntıları sağlayıcı adaptöründe doğrulanır.

GCM nonce'u aynı anahtarla tekrar kullanılmamalıdır. SDK yüksek seviyeli işlemlerde nonce'u kendisi üretir; uzun ömürlü anahtarlar için mesaj sayısı ve veri hacmi limitleri uygulanır. Salt rastgele nonce üretimi sınırsız kullanım garantisi sayılmaz. Envelope dosyalarında taze veri anahtarı ve aşağıdaki chunk sayaç şeması tercih edilir.

### 7.3 Şifreli veri formatı

İki ayrı düzey tasarlanacak:

- Primitive API: nonce, AAD, ciphertext ve tag açık parametrelerle; dış formatlarla çalışmak isteyen uzman kullanıcılar için.
- Envelope API: sürümlü, kendi kendini tarif eden çıktı; normal uygulama kullanımı için.

Envelope başlığı: magic, format version, suite ID, flags, header length, key reference veya wrapped data key, KDF tanımı/salt/parametreler, nonce bilgisi, chunk düzeni ve gerekiyorsa kaynak metadata'sı. Alan uzunlukları üst sınırla doğrulanır; byte sırası ve canonical encoding format şartnamesinde sabitlenir.

Kimlik, algoritma ve uzunluk alanları dahil yorumlamayı etkileyen başlık verileri AAD ile korunur. Anahtar veya parola başlığa konmaz. Ayrıştırılan KDF değerleri doğrulanmadan pahalı işlem başlatılmaz; saldırganın aşırı iterasyon/bellek isteği reddedilir. Bilinmeyen kritik alan/sürüm sessizce yok sayılmaz.

Envelope tasarımı SDK'ya özgü bir protokoldür; standart bir kripto algoritması kullanılması formatın otomatik güvenli olduğunu göstermez. Ayrı format şartnamesi, test vektörleri ve güvenlik incelemesi tamamlanmadan kalıcı format dondurulmaz.

### 7.4 Büyük dosya ve chunk tasarımı

Başlangıç I/O buffer önerisi 1 MiB, ayarlanabilir; nihai değer ölçümle seçilir. Bellek tüketimi toplam dosya boyutuyla değil, chunk boyutu × eşzamanlı iş sayısıyla sınırlanır.

Önerilen chunk formatı:

1. Her mesaj/dosya için yeni 256-bit veri anahtarı CSPRNG ile üretilir. Kullanıcı KEK'i, parola KDF anahtarı veya alıcı public key bu veri anahtarını uygun tanımlı yöntemle sarar.
2. Veri chunk nonce alanı için 96-bit içinde sabit domain/prefix ve monoton chunk index ayrılır. Anahtar sarma ile veri şifreleme anahtarları/domain'leri ayrıdır.
3. Chunk AAD'si canonical header bağını, mesaj kimliğini, index'i, uzunluğu ve final-record türünü içerir.
4. Zorunlu doğrulanmış final record toplam chunk ve plaintext byte sayısını bağlar; boş dosyanın da final kaydı vardır.
5. Tekrar, sıra değiştirme, başka dosyadan chunk ekleme, kırpma ve final sonrası veri reddedilir.
6. Sayaç taşması ve suite başına byte/mesaj limitleri aşılmadan işlem durdurulur. Devam ettirme v1'de yoktur; retry yeni veri anahtarı/nonce alanıyla başlar.

Bu şema öneridir. Nonce alanlarının tam bit dağılımı, limitler, başlık kodlaması ve anahtar sarma yöntemi Faz 3 şartnamesinde kesinleştirilir.

### 7.5 Doğrulanmamış plaintext ve çıktı commit'i

- Byte/string çıktısı tag ve bütün mesaj kontrolü başarıyla tamamlanmadan kullanıcıya verilmez.
- File çıktısı erişimi sınırlandırılmış geçici dosyaya yazılır; doğrulama bitince aynı hedef birimde commit edilir. Hedef mevcutsa varsayılan hata; overwrite açık seçenektir.
- Strict stream çıkışı varsayılandır: tüm mesaj doğrulanana kadar staging gerekir. Sink transactional değilse bounded bellek/disk staging kullanılır; izin/kota yoksa işlem baştan reddedilir.
- Opsiyonel verified-chunk stream modu yalnız kendi tag'i doğrulanmış chunk'ları teslim eder. Tam mesajın eksiksizliği final record'a kadar bilinmez; kullanıcı bu farklı sözleşmeyi açıkça seçer.
- Yanlış key/tag, iptal veya hata halinde normal hedef başarıyla tamamlanmış gibi görünmez; geçici kaynaklar kapatılır ve temizleme hatası raporlanır.
- Diskte geçici plaintext bulunması ayrı bir tasarım risktir. Politika disk staging'i kapatabilir. Dosya silmek fiziksel güvenli silme garantisi değildir.

## 8. Hashing

`Hasher` varsayılan SHA-256; ilk sürüm SHA-384 ve SHA-512 de hedeflenir. Tek seferlik `compute` ve `HashSession.update/finalize` sunulur. SHA-1/MD5 yalnız açık legacy checksum gereksiniminde düşünülecek; yeni güvenlik profillerinde etkin olmayacak.

- Dosyalar chunk'larla okunur; boş veri geçerli girdidir.
- String hash'i explicit encoding'in byte'ları üzerindedir. Satır sonu, BOM ve Unicode normalization otomatik değiştirilmez.
- `computeMany` her girdi için ayrı digest döndürür; strings/streams örtük birleştirilmez.
- `MultiHasher` sonraki optimizasyon olarak tek okumadan birkaç digest üretebilir.
- HMAC ayrı `MacService` üzerinden sunulur; düz hash, kimlik doğrulanmış MAC veya parola saklama algoritması olarak gösterilmez.
- Parola saklama ihtiyacı ayrı `PasswordHasher` genişlemesidir. Şifreleme anahtarı türetmek için kullanılan `KeyDeriver` ile karıştırılmaz.

Klasör hash'i canonical manifest üzerinden tanımlanır: normalize edilmiş göreli yol, öğe tipi, dosya uzunluğu, algoritma kimliği ve içerik digest'i. Kayıtlar açık byte sırasıyla sıralanır ve uzunluk önekleriyle kodlanır. Boş dizinler kayıt edilir. Timestamp ve ACL varsayılan içerik digest'ine dahil değildir; profil açıkça isterse dahil edilir. Aynı profil ve aynı veri farklı sağlayıcılarda aynı manifest digest'ini üretmelidir.

## 9. Signing

`Signer` özel anahtarla çalışır; ilk hedefler RSA-PSS/SHA-256 ve ECDSA P-256/SHA-256. RSA anahtar boyutu politika ile sınırlandırılır; başlangıçta 3072-bit varsayılan önerilir. Başka boyutlar birlikte çalışabilirlik profiliyle seçilir. PSS salt length, MGF1 digest ve ECDSA encoding açıkça sabitlenir.

- `signMessage`: SDK mesajı uygun profile göre işler.
- `signDigest`: yalnız destekleyen imza profillerinde, digest algoritması ve boyutu açık verilerek kullanılır; çift hash yapılmaz.
- Varsayılan dosya imzası detached olur. İçeriği taşıyan signed package ayrı format olarak tasarlanır.
- `signManifest` klasörün kapsamını, yollarını ve içerik digest'lerini canonical manifest üzerinden imzalar.
- İmza paketi sürüm, suite, digest, key fingerprint, signature encoding ve imza byte'larını içerir. Kararı etkileyen metadata imzalı girdiye bağlanır.
- CNG ECDSA ham `r||s` ile DER gibi farklı gösterimler dış format adaptöründe dönüştürülür; uygulama sağlayıcının ham biçimine bağımlı olmaz.
- Signature context/domain bilgisi belge formatında sabitlenir; farklı amaçlardaki imzalar birbirinin yerine kabul edilmez.
- Donanım/KSP özel anahtarlarında PIN/UI gereksinimi önceden capability ve çalışma politikasıyla ele alınır; servis uygulamasında kendiliğinden UI açılmaz.

Ed25519/Ed448 ve başka signature suite'leri sonraki sağlayıcılarda gerçek yetenek sorgusuyla eklenir. Bütün imza algoritmaları aynı streaming/prehash kurallarına zorlanmaz.

## 10. Verification

`Verifier`, mesaj/digest/manifest imzasını public key veya desteklenen key reference ile doğrular.

Sonuç ayrımı:

| Durum | Anlam |
| --- | --- |
| `Valid` | İstenen profil altında kriptografik doğrulama başarılı |
| `Invalid` | İmza veriye/anahtara uymuyor veya bütünlük doğrulaması başarısız |
| `Indeterminate` | Gerekli algoritma/anahtar/güven bilgisi yok; karar verilemiyor |
| Teknik hata | Okuma hatası, bozuk format, provider hatası gibi çalıştırma sorunu |

`Valid` anahtar sahibinin güvenilir olduğunu kendiliğinden göstermez. Sertifika zinciri, süre, iptal, timestamp ve OpenPGP trust kararları ayrı `TrustResult` alanında değerlendirilir; değerlendirilmediyse `NotEvaluated` döner.

Sertifikayla doğrulamada `CertificateManager.validate` sonucu ile `Verifier` imza sonucu ayrı alanlarda korunur. Güven gerektiren profil ancak imza geçerli ve sertifika güven politikası başarılıysa genel başarı üretir. Certificates sözleşmesi bölüm 25'te tanımlıdır.

`compareDigest` beklenen hash ile byte eşitliğini kontrol eder. `verifyMac` ise ayrı anahtarlı doğrulamadır. Bu işlemler dijital imza doğrulamasıyla isim ve sonuç tipi açısından ayrılır.

Manifest doğrulamasında değişen, eksik, fazla ve yeniden adlandırılmış öğeler ayrı raporlanır. `ExactTree` modu fazladan dosyaları da hata sayar; `ListedEntriesOnly` modu yalnız manifestteki öğeleri kontrol eder. Varsayılan tam klasör bütünlüğü için `ExactTree` olur.

## 11. RandomNumber Generation

`RandomGenerator` Windows başlangıcında sistem tercihli `BCryptGenRandom` kaynağını kullanır. API boyut sınırından büyük istekler parçalara ayrılır. [Microsoft BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom)

- `fill`: caller-owned tamponu doldurur.
- `generateBytes`: sahipli byte buffer döndürür.
- `uniformInteger(min, max)`: kapalı aralıkta rejection sampling ile modulo bias olmadan üretir; tam tür aralığı ve taşma özel işlenir.
- `generateTo(sink, byteCount)`: dosya/stream'e sınırlı bellekle üretir; progress ve cancellation destekler.
- `generateToken`: açık alphabet/encoding üzerinden token üretir; karakter seçimi bias oluşturmaz.
- Key ve nonce üretimi ilgili yüksek seviye servislerden yapılır; kullanım amacı ve boyut politikası burada doğrulanır.

Üretimde `rand`, zaman damgası veya uygulama tarafından tahmin edilebilir seed fallback'i yoktur. RNG hatasında işlem hata verir. Deterministik RNG yalnız test amaçlı bağımlılık olarak bulunur ve production paketinde yanlışlıkla seçilememelidir.

RNG için folder/files/streams “girdi üzerinde kripto işlemi” değildir: üretilen verinin hedefleridir. Toplu üretimde her hedefe bağımsız üretim yapılır; aynı buffer bütün dosyalara kopyalanmaz. İstatistik testlerinin geçmesi tek başına kriptografik güvenlik kanıtı olarak sunulmaz.

## 12. Anahtar yönetimi ve güvenlik politikası

### 12.1 Anahtar tipleri ve sahiplik

`SymmetricKey`, `PublicKey`, `PrivateKey`, `PasswordSecret` farklı wrapper türleri olur. Key descriptor algoritma, boyut, kullanım izinleri, sağlayıcı kimliği, storage türü ve exportability içerir. Private key ile public key'nin yanlış yerde kullanılması mümkün olduğunca API seviyesinde engellenir; C sınırında runtime doğrulanır.

İlk sürüm ephemeral anahtarlar; ardından NCrypt kalıcı anahtarlar. Key reference içinde alias, provider ve gerekiyorsa version bulunur. Rotasyonda yeni şifreleme yeni sürümü, eski verinin çözülmesi ilgili eski anahtarı kullanır. Anahtar silme dosyaları otomatik yeniden şifrelemez ve ayrı açık işlemdir.

### 12.2 Parola ve KDF

İlk parola profili CNG PBKDF2-HMAC-SHA256'dır. Salt en az 128-bit rastgele önerilir. İş yükü hedef makinede süre hedefi ve minimum politika ile belirlenir; parametreler envelope'a yazılır ve çözmede alt/üst sınırlar kontrol edilir. [Microsoft PBKDF2 API](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2)

Sonraki sağlayıcılarda Argon2id gibi seçenekler capability ve versiyonlanmış profil olarak eklenebilir; ilk CNG sürümünde destekleniyor sayılmaz. Parola doğrulama hatası ile AEAD authentication hatası dışarıya hassas ayrıntı sızdıracak biçimde ayrıştırılmaz.

### 12.3 Güvenli varsayılanlar

- Anahtar, parola ve plaintext loglanmaz; progress/event payload'ları sır içermez.
- `SecureBuffer` kontrollü silme yapar. Swap, crash dump veya önceki uygulama kopyalarının tamamen temizlenmesini garanti etmez.
- Harici anahtar formatları explicit olarak belirtilir; provider-native blob ile PEM/DER aynı şey değildir. Dönüşüm codec'i olmayan format `UnsupportedFormat` verir.
- Export edilemeyen anahtar için örtük export veya sağlayıcı değiştirme yapılmaz.
- Default, LegacyInterop ve Experimental politikaları ayrı olur; Legacy/Experimental açık seçilir.
- FIPS durumu algoritma adına bakarak ilan edilmez; modül, sürüm, yapılandırma ve doğrulanmış kapsam kanıtı gerekir. İlk SDK için FIPS sertifikası iddiası yoktur.

## 13. File/files, folder/folders, stream/streams, string/strings ve byte desteği

### 13.1 Ortak I/O sözleşmesi

`IByteSource`: read, optional length, optional seek, close/lifetime. `IByteSink`: write, optional flush, commit/abort. Her source seek edilebilir veya uzunluğu önceden bilinen bir nesne kabul edilmez.

Kısa okuma/yazma normal biçimde işlenir; EOF ile hata ayrılır. Bloklayıcı read'in iptal edilebilirliği adaptör capability'sidir. Var olan stream'in işlem öncesi konumu başlangıç noktasıdır; kendiliğinden rewind yapılmaz. Stream'in kapatılma sahipliği açık seçenektir.

STL ve VCL stream adaptörleri kendi istemci derleyicisinde çalışır; C callback köprüsü üzerinden byte aktarır. Bu callback'lerin hangi thread'de çağrılacağı senkron/asenkron sözleşmeyle aynıdır.

### 13.2 Davranış matrisi

| Veri biçimi | Encrypt/Decrypt | Hash | Sign/Verify | RNG |
| --- | --- | --- | --- | --- |
| Byte buffer | Envelope veya explicit primitive çıktı | Digest | Mesaj/digest imzası | Tampon doldurma |
| String | Encoding sonrası byte işlemi; çıktı binary/base64 | Encoding byte'larının digest'i | Aynı byte temsili üzerinde | Token veya encoded byte |
| Strings | Öğe başına bağımsız sonuç | Öğe başına digest | Öğe başına imza/sonuç | Token koleksiyonu |
| File | Akışlı okuma, güvenli commit | Akışlı digest | Detached imza | Belirli boyutta dosya üretimi |
| Files | Batch ve öğe sonuçları | Digest listesi | İmza listesi/manifest | Bağımsız dosya üretimleri |
| Folder | Ağacı koruyan dosya batch'i | Canonical manifest digest | Manifest imzası | Açık plana göre dosya üretimi |
| Folders | Kök kimlikli bağımsız batch'ler | Kök başına manifest | Kök başına imza | Açık hedef planları |
| Stream | Staging/transaction veya açık chunk sözleşmesi | Artımlı digest | Profil destekliyorsa artımlı | İstenen byte sayısını yazma |
| Streams | Öğe kimlikli batch | Akış başına digest | Akış başına sonuç | Her sink'e bağımsız üretim |

### 13.3 Klasör işlemleri

İlk folder encryption modu her dosyayı bağımsız envelope olarak üretir, göreli dizin yapısını korur. Dosya adlarının/sayılarının gizliliğini sağlamaz. Dosya adlarını da saklayan tek encrypted container ayrı sonraki özelliktir; bunun için güvenli arşiv biçimi gerekir.

Varsayılanlar:

- Alt klasörler dahil; include/exclude filtreleri ve maksimum derinlik ayarlanabilir.
- Symlink/junction/reparse point takip edilmez. İzin verilirse döngü algılama ve kaynak/hedef kök sınırları doğrulanır.
- Hedefin kaynak altında olması ve aynı kaynak/hedef dosya varsayılan reddedilir; çıktının yeniden girdiye dönüşmesi engellenir.
- Birden fazla kökte aynı adlar namespace/root ID ile ayrılır; overwrite sessiz gerçekleşmez.
- Relative path traversal, absolute path, Windows özel cihaz adları, ADS ve normalization/case çakışmaları denetlenir.
- Boş klasörler metadata kaydıyla korunur. ACL, ADS ve bütün NTFS metadata'sı ilk sürümde tam korunmuş sayılmaz.
- Dosya keşfi ön değerlendirme üretir; erişim hatası ve değişen kaynak davranışı belirlenir. Varsayılan değişen kaynakta `SourceChanged` hatasıdır.
- Tam klasör snapshot garantisi yoktur. Tutarlı snapshot gerekiyorsa uygulamanın sağladığı snapshot kaynağı veya sonraki VSS entegrasyonu gerekir.

### 13.4 Batch sonucu ve transaction sınırı

Varsayılan bağımsız dosya işlerinde `ContinueOnError` ve öğe sonuçları kullanılır; kullanıcı `StopOnFirstError` seçebilir. Transaction dosya düzeyindedir. Bütün klasör için atomik commit iddiası yoktur. Manifest/signed bundle gibi bütüncül çıktılarda herhangi bir öğe hatası nihai paketin başarıyla commit edilmesini engeller.

İptalde tamamlanmış dosyalar sonuç listesinde kalır; devam eden öğenin staging çıktısı iptal edilir; başlamayanlar `NotStarted/Cancelled` olarak gösterilir. Bütün başarılı dosyaları geri alma ancak ayrı rollback seçeneğiyle tasarlanır.

## 14. Callback, progress ve event tasarımı

### 14.1 Bildirim modeli

C sınırında callback fonksiyon pointer'ı + `void* user_data`; C++ tarafında `IEventSink` ve modern wrapper'da lambda/std::function adaptörü. VCL için sürüme uygun event adaptörü ayrı pakettedir.

Olaylar: `OperationStarted`, `PhaseChanged`, `ItemStarted`, `ProgressChanged`, `ItemCompleted`, `Warning`, `OperationCompleted`, `OperationFailed`, `OperationCancelled`. Her işlem yalnız bir terminal olay üretir.

`ProgressInfo`: operation ID, item ID, phase, işlenen input byte, üretilen output byte, biliniyorsa toplam input, işlenen/toplam item, süre, isteğe bağlı hız. Yüzde bilinmiyorsa unknown olarak bildirilir; sahte toplam üretilmez.

Keşif, KDF/key generation, okuma/kripto, doğrulama ve commit ayrı phase'lerdir. Bir provider çağrısı kendi içinde progress sunmuyorsa SDK o aşamayı belirsiz ilerleme olarak gösterir. %100, doğrulama ve commit tamamlanmadan başarı anlamına gelmez.

### 14.2 Thread ve yaşam süresi

- Senkron API varsayılan callback'leri çağıran thread'de çalıştırır.
- Asenkron API varsayılan callback'leri worker üzerinde çalıştırır; UI güncellemek isteyen uygulama `IEventDispatcher` sağlar.
- VCL dispatcher olayları UI kuyruğuna aktarır; worker doğrudan kontrol nesnesine dokunmaz.
- Bir işlem için olaylar sırayla teslim edilir; farklı işlemler arasında toplam sıralama garantisi yoktur.
- Callback çağrılırken iç kilit tutulmaz. Callback içinden aynı işlemde blocking wait, destroy veya recursive update desteklenmez; iptal talebi güvenlidir.
- Subscription kapatılırken kuyruklanmış olay ve kullanıcı context yaşam süresi açık yönetilir. Kapatma sonrası callback yok garantisi `unsubscribeAndDrain` ile sağlanır; dispatcher thread'inde kendini bekleme yasaktır.
- Callback'te oluşan C++ exception istemci adaptöründe yakalanır; DLL sınırını geçmez. Bildirim hatası terminal olay döngüsü oluşturmaz.
- Progress bildirimleri örneğin 100 ms aralıkta birleştirilebilir; başlangıç ve terminal olaylar kaybolmaz. Kuyruk kapasitesi sınırlıdır.

Secret/PIN talebi progress event'i değildir; ayrı credential callback sözleşmesi olur. UI gereksinimi, timeout ve cancellation tanımlanır; sır normal event kuyruğuna kopyalanmaz.

## 15. Asenkron çalışma ve iptal

Senkron API çekirdek davranıştır. Asenkron yürütücü aynı operasyonu sınırlı worker pool içinde çalıştırır. `OperationHandle` status, cancel, wait ve result sağlar; modern wrapper uygun hedefte future'a uyarlayabilir.

Durum makinesi:

```text
Created -> Queued -> Running -> Finalizing -> Committing -> Succeeded
              |         |           |             |
              +---------+-----------+-------------+--> Failed
              +---------+-----------> Cancelled
```

İptal işbirlikçidir. Tek parça KDF, key generation veya bloklayıcı üçüncü taraf çağrısı hemen kesilemeyebilir; thread zorla öldürülmez. Commit kritik bölgesi başladıktan sonra iptal geç gelmiş sayılabilir; gerçekleşen sonuç doğru raporlanır. `wait` sonucunun hazır olmasıyla UI kuyruğundaki terminal olayın teslim edilmiş olması farklıdır.

Servis konfigürasyonu işlem sırasında immutable olur. Bir session aynı anda iki thread'den update almaz. Paylaşılan anahtarın eşzamanlı kullanılabilirliği sağlayıcı capability'sine göre serialize edilir. Otomatik yeniden deneme yalnız güvenli/yan etkisiz noktalarda yapılabilir; nonce ve çıktı tekrar kullanımı yaratmaz.

## 16. Script yeteneği

Önerilen dil Lua; opsiyonel modül olarak eklenecek. Lua gömülebilir C API sunar, dolayısıyla istemci derleyici türlerinden bağımsız binding oluşturmak için uygundur. [Lua resmi kılavuzu](https://www.lua.org/manual/5.4/manual.html)

Script kapsamı: dosya listesi hazırlama, hash, encrypt/decrypt, sign/verify, random token üretimi, sertifikalar, batch yönetimi ve progress aboneliği. TLS/SSH modülleri eklendiğinde ağ hedefi/port, remote command ve dosya aktarımı için ayrı script izinleri tanımlanır. Script kriptografik primitive implementasyon dili olarak kullanılmayacak; aynı SDK servislerini çağıracak.

Tasarlanan nesneler: `ScriptEngine`, `ScriptContext`, `ScriptPolicy`, `ScriptResult`. Script key referansı opaque userdata olur; private key/parola sıradan Lua string'ine otomatik dönüştürülmez. Bir Lua state eşzamanlı thread'lerden çağrılmaz; worker bildirimleri sahibi olan thread'e aktarılır.

Politika: izinli API ve klasör kökleri, dosya/bellek/çalışma süresi kotaları, açık provider izinleri. `os`, `io`, `debug`, native modül yükleme ve process çalıştırma varsayılan açılmaz. Instruction hook ve allocator limitleri uygulanır; native bloklayıcı çağrıların da kendi limit/iptal sözleşmesi bulunur.

Bu kısıtlar süreç içi Lua'yı tam güvenlik sınırı yapmaz. Kullanıcıya ait güvenilmeyen script çalıştırılması hedeflenirse ayrı worker process ve OS izolasyonu gerekir. İlk script sürümü uygulamanın güvenilir iş akışları içindir. Binding hata geçişleri C++ RAII nesnelerini Lua longjmp üzerinden atlamayacak şekilde tasarlanır.

## 17. OpenPGP / PGP desteği

PGP tek bir cipher veya kütüphane değildir. OpenPGP, mesaj/anahtar biçimleri ve işlem kuralları tanımlar. Bu nedenle AES/SHA sağlayıcısına düz bir alternatif gibi ele alınmayacak. RFC 9580 güncel temel biçim referansıdır; hedef alıcıların eski format ihtiyacı açık interoperability profiliyle yönetilir. [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580.html)

`OpenPgpService`: encrypt/decrypt message, sign/verify, import/export key, ASCII armor, birden fazla alıcı ve detached signature. RNP birincil değerlendirme adayı; mevcut GnuPG keyring/agent iş akışı gerekiyorsa GPGME alternatifi.

Karar noktaları: desteklenen key/message sürümleri, sıkıştırma limitleri, keyring konumu, passphrase callback, expiry/revocation/trust sonucu ve dış engine kurulumu. Capability “OpenPGP destekli” boolean'ından daha ayrıntılı olacak. SDK envelope ile OpenPGP dosyası birbirine karıştırılmayacak; format açık seçilecek.

## 18. Custom C++ algoritma implementasyonları

`CustomProvider`, diğer sağlayıcılarla aynı sözleşmeleri uygular. Eğitim, kontrol ve özel geliştirme için standart algoritmaların kendi implementasyonlarımızı barındırabilir; yeni/proprietary algoritmalar benzersiz ad ve format kimliği alır.

Kabul sırası: algoritma şartnamesi → bilinen cevap vektörleri → bağımsız sağlayıcı karşılaştırması → sınır/hata testleri → fuzzing → yan kanal ve secret-dependent branch/table incelemesi → bağımsız güvenlik değerlendirmesi.

Round-trip testinin geçmesi güvenlik doğrulaması sayılmaz. AES/SHA adıyla davranışı değiştirilmiş algoritma kaydedilmez. İncelenmemiş custom implementasyon `Experimental` kalır ve varsayılan sağlayıcı sırasına girmez. RNG için kendimize ait entropy kaynağı uydurulmaz; deterministik test kaynağı üretim RNG'sinden ayrıdır.

## 19. Use case'ler

| No | Senaryo | API akışı | Beklenen sonuç / hata davranışı |
| --- | --- | --- | --- |
| UC-01 | Türkçe metin şifreleme | TextSource UTF-8 → Encryptor → envelope/base64 | Aynı byte temsili kayıpsız geri alınır |
| UC-02 | Byte dizisi koruma | ByteView → Encryptor → ByteBuffer | Null byte'lar korunur; uzunluk açık |
| UC-03 | Büyük dosya çözme | FileSource → Decryptor → staging → commit | Bellek sınırlı; bozuk tag'de hedef commit edilmez |
| UC-04 | Çok dosya şifreleme | Files → BatchProcessor → item sonuçları | Progress, iptal ve kısmi hata raporu |
| UC-05 | Klasör ağacı koruma | FolderSource → dosya batch'i + manifest | Göreli yapı korunur; isimlerin gizli olmadığı belgelenir |
| UC-06 | Çok klasör işleme | Kök ID'li Folders → bağımsız batch | Çakışan adlar overwrite yaratmaz |
| UC-07 | Stream hash | Callback/STL/TStream → HashSession | Seek gerekmez; bilinmeyen uzunluk desteklenir |
| UC-08 | Birden çok stream | Streams → bounded batch | Her stream ayrı kimlik ve sonuç alır |
| UC-09 | Dosya imzalama | FileSource → Signer → detached signature | Verifier aynı public key ile kontrol eder |
| UC-10 | Klasör imzası | ManifestService → Signer | Değişen/eksik/fazla dosya belirlenir |
| UC-11 | Parolayla şifreleme | PasswordSecret → KDF → wrapped DEK → AEAD | Yanlış parola plaintext açığa çıkarmaz |
| UC-12 | Rastgele token/dosya | RandomGenerator → buffer/string/file sink | Aralıkta bias yok; RNG hatası gizlenmez |
| UC-13 | CNG'den OpenSSL'e geçiş | Aynı profil + uygun aktarılabilir key + yeni provider | Veri formatı korunur; eksik capability açık hata |
| UC-14 | VCL arayüzü | Async operation → VCL dispatcher | UI thread'de progress, iptal; kapanışta geç callback yok |
| UC-15 | Kalıcı özel anahtar | KeyManager.open NCrypt → Signer | Private key export edilmeden imza |
| UC-16 | Script ile otomasyon | Lua → mevcut servisler → batch raporu | Politika ve dosya kökü sınırları korunur |
| UC-17 | OpenPGP alıcıları | OpenPgpService → birden çok public key | Seçilen karşı uygulamayla birlikte çalışabilir mesaj |
| UC-18 | Sağlayıcı karşılaştırması | Aynı vektörler → CNG/Crypto++/Botan/OpenSSL/Custom | Cipher/digest uyumu, imzada çapraz doğrulama |
| UC-19 | Sertifika inceleme/dönüştürme | File/bytes/PEM → CertificateManager → DER/PEM | Subject, issuer, SAN, geçerlilik ve fingerprint raporu |
| UC-20 | Windows sertifikasıyla imza | Store.find → bağlı KeyHandle → Signer | Private key export edilmeden imza; güven sonucu ayrıca raporlanır |
| UC-21 | Sertifika güven kontrolü | Certificate + intermediates + trust policy → validate | Zincir, kullanım amacı, süre ve revocation ayrı sonuçlar |
| UC-22 | CSR ve self-signed sertifika | KeyManager → CertificateRequestBuilder / CertificateBuilder | CSR oluşturulur veya açık test/yerel kullanım sertifikası üretilir |
| UC-23 | PFX aktarımı ve toplu sertifika kontrolü | Secret callback + PFX veya files/folders → CertificateManager | Açık key persistence/export politikası, öğe sonuçları ve progress |
| UC-24 | TLS üzerinden veri aktarımı | TlsClient → handshake + server identity → TlsStream | Peer doğrulanmadan uygulama verisi gönderilmez |
| UC-25 | Karşılıklı TLS | TlsClient/TlsServer + CertificateManager + KeyHandle | İki tarafın sertifika ve kullanım politikası doğrulanır |
| UC-26 | SSH komut çalıştırma | SshClient → host key check → authenticate → exec | stdout/stderr sınırlı stream, exit status ayrı sonuç |
| UC-27 | SFTP dosya/klasör aktarımı | SftpClient + File/Folder/Stream adapters → batch | Progress/iptal ve öğe bazında commit sonucu |
| UC-28 | SSH host key değişikliği | KnownHostsStore → uyuşmazlık | Parola/key authentication başlamadan bağlantı reddedilir |

## 20. Hata modeli, loglama ve tanılama

Hata kategorileri: `InvalidArgument`, `UnsupportedAlgorithm`, `UnsupportedFormat`, `ProviderUnavailable`, `KeyNotFound`, `KeyUsageDenied`, `AuthenticationFailed`, `MalformedData`, `IoError`, `SourceChanged`, `Cancelled`, `ResourceLimitExceeded`, `CallbackError`, `AbiMismatch`, `InternalError`.

Her sonuç SDK kodu, güvenli mesaj, operation/item ID ve gerektiğinde native hata domain/kodunu taşır. İmza uyumsuzluğu normal verification sonucu; disk okuma hatası teknik hatadır. Hata mesajları log politikasına göre dosya yolu gibi kişisel bilgileri maskeleyebilir.

Tanılama sürüm, provider capability ve çalışma konfigürasyonunu verir; anahtar/parola/plaintext dökmez. Plugin yükleme yalnız izinli tam yollarla yapılır; mevcut çalışma dizininden kontrolsüz DLL araması kullanılmaz. Plugin kapatma aktif handle'lar varken engellenir.

## 21. Teknoloji, proje yapısı ve dağıtım

Önerilen araçlar: ortak çekirdekte C++03 uyumlu alt küme, MSVC ve C++Builder toolchain'leri, Windows SDK, CMake + CTest, toolchain'e uygun C++Builder proje dosyaları, Doxygen API belgesi. Modern wrapper ve sağlayıcı modülleri gerekli dil seviyesini kendi hedefinde seçer. Eski C++Builder hedefleri için güncel CMake generator desteği varsayılmaz; sürüme uygun proje/make dosyaları ve build script'leri sağlanır. GoogleTest veya Catch2 gibi bir test çatısı modern test host'unda kullanılabilir; classic derleyici için aynı vektörleri okuyan hafif conformance runner hazırlanır. Test çatısı istemci SDK bağımlılığı olmayacak.

```text
projects/msvc/All/          # All.sln: Visual Studio projelerinin ortak solution'ı
projects/msvc/AppBuilder/   # Visual Studio EXE üretim projesi
projects/msvc/AppRunner/    # Visual Studio uygulama çalıştırıcı projesi
projects/msvc/DllBuilder/   # Visual Studio DLL üretim projesi
projects/msvc/DllRunner/    # Visual Studio DLL çalıştırıcı projesi
projects/msvc/LibBuilder/   # Visual Studio statik LIB üretim projesi
projects/msvc/LibRunner/    # Visual Studio LIB çalıştırıcı projesi
src/include/aycrypto/c/     # Sabit C ABI public başlıkları
src/include/aycrypto/cpp/   # Ortak C++ wrapper ve template'ler
src/include/aycrypto/modern/ # İsteğe bağlı modern kolaylıklar
src/core/                  # Context, hata, policy, lifetime
src/services/              # Altı ana servis ve yardımcılar
src/io/                    # File, stream, staging, batch adaptörleri
src/formats/               # Envelope, manifest, signature package
src/certificates/          # X.509 modelleri, depo, CSR ve güven politikası
src/network/               # Winsock ve duplex transport sözleşmesi
src/protocols/tls/         # TLS servisleri ve Schannel adaptörü
src/protocols/ssh/         # SSH/SFTP servisleri ve sağlayıcı köprüsü
src/providers/windows/     # CNG, NCrypt ve DPAPI adaptörleri
src/providers/cryptopp/    # Opsiyonel modül
src/providers/botan/       # Opsiyonel modül
src/providers/openssl/     # Opsiyonel modül
src/providers/custom/      # Kendi implementasyonlarımız
src/integrations/vcl/      # Sürüme uygun VCL adaptörü
src/integrations/lua/      # Script binding
src/integrations/openpgp/  # OpenPGP protokol katmanı
src/cli/                   # Ortak komut ayrıştırma ve CLI iş akışları
src/runner_support/        # Çalıştırıcıların paylaştığı yardımcı kodlar
tests/                     # Vektör, ABI, I/O, negatif ve concurrency testleri
fuzz/                      # Format/parser test hedefleri
examples/msvc/             # Console ve Windows örnekleri
examples/cppbuilder/       # Console ve VCL örnekleri
projects/cppbuilder/       # Altı native C++Builder projesi ve All/All.groupproj
docs/                      # API, format ve karar kayıtları
packaging/                 # Dağıtım, export ve bağımlılık tanımları
```

Kullanıcı kararı: Microsoft Visual Studio projeleri `projects/msvc`, C++Builder projeleri `projects/cppbuilder` altında gruplanır; her iki grubun kullanacağı ortak SDK kodları kökteki `src` altında tutulacaktır. Yukarıdaki `src` alt dizinleri hedef yapıdır; tasarım aşamasında implementasyon dosyaları oluşturulmuş sayılmaz. Public başlıkların kaynak konumu da `src/include/aycrypto` olacaktır; dağıtım paketindeki `include/aycrypto` bu başlıklardan üretilecektir.

Mevcut Visual Studio proje klasörlerinde `.sln`/`.vcxproj`, projeye özgü giriş noktaları ve derleme ayarları bulunacak. Kriptografi, sertifika ve protokol mantığı proje klasörlerine kopyalanmayacak. `projects/cppbuilder` altındaki `.cbproj` projeleri de aynı `src` dosyalarını kendi toolchain'leriyle kullanacak; mevcut `.vcxproj` dosyalarının C++Builder projesi olduğu varsayılmayacak.

Her sürüm header'lar, x86/x64 DLL, DLL import library'leri, toolchain'e özel gerçek statik LIB'ler, DLL Runner, LIB Runner, CLI EXE, örnekler, API/format sürümleri, üçüncü taraf bildirimleri ve test edilmiş uyumluluk matrisi içerir. Debug/Release ve CRT kombinasyonları açık belgelenir. Bağımlılıklar pinlenir, checksum/SBOM kaydı ve güncelleme süreci tutulur.

Semantic version SDK public API için kullanılır; C ABI major ve dosya format version ayrı numaralardır. Yeni capability eklemek eski istemciyi bozmaz; eski istemcinin anlamadığı kritik format özelliği açık hata verir. Eski dosyaları okuma test corpus'u sürümler arasında korunur.

### 21.1 İstenen ürünlerin somut ayrımı

Ürün adı `CryptoAPI` olarak belirlenmiştir. Çıktı adları aşağıdaki biçimde kullanılacak; toolchain/mimari varyantları ayrı paket dizinlerinde tutulacaktır.

| Ürün | Örnek çıktı | Bağlantı / kullanım |
| --- | --- | --- |
| C++ sınıfları | `include/aycrypto/...` | `src/include/aycrypto` kaynaklarından paketlenir; aynı public sınıflar üzerinden DLL veya static backend seçimi |
| DLL | `CryptoAPI.dll` | Ortak C ABI; uygulama wrapper üzerinden veya doğrudan C fonksiyonlarıyla çağırır |
| DLL import LIB | `CryptoAPI_import.lib` | DLL'e link-time bağlanmak için; kripto çekirdeğini içermez |
| DLL Runner | `CryptoAPI_DllRunner.exe` | İstenen tam yoldaki DLL'i runtime yükler, ABI kontrol eder ve işlem çalıştırır |
| Statik LIB | `CryptoAPI_static.lib` | Çekirdek + seçili yerleşik sağlayıcılar uygulamaya link edilir |
| LIB Runner | `CryptoAPI_LibRunner.exe` | Statik LIB'e build sırasında bağlanır; temel CNG profili SDK DLL olmadan çalışır |
| EXE | `CryptoAPI_Cli.exe` | Son kullanıcı/otomasyon için encrypt, decrypt, hash, sign, verify, random ve batch komutları |

LIB Runner bir `.lib` dosyasını runtime'da açıp çalıştıran araç değildir; LIB link aşamasında EXE'ye katılır. Windows sistem DLL'lerine bağımlılık doğal olarak sürer. “SDK DLL olmadan çalışma” tüm Windows DLL'lerinden bağımsızlık anlamına gelmez.

### 21.2 Ortak kod ve bağlantı modeli

Tek kripto implementasyonu korunur. Aynı kaynaklardan statik çekirdek ve DLL export katmanı üretilir. Public C++ wrapper, build seçeneğine göre DLL import tablosunu veya statik bağlanan C fonksiyonlarını çağırır. Static/DLL seçim makroları tek yapılandırma başlığında tutulur; aynı target içinde çelişen seçim derleme hatasıdır.

`DllBuilder` ve `LibBuilder` gerekli ortak `.cpp` dosyalarını `src` üzerinden dosya referanslarıyla derler; `.cpp` dosyaları `#include` edilmez ve kopyalanmaz. `AppBuilder` seçilen bağlantı modeliyle asıl CLI EXE'yi üretir. Runner'lar public API ve `src/runner_support` yardımcılarını kullanır; `LibRunner` statik kütüphaneye bağlanır, `DllRunner` DLL yükler. `AppRunner` için önerilen görev, AppBuilder'ın ürettiği EXE'yi ayrı süreçte çağırarak argüman/stdout/stderr/exit code sözleşmesini test etmektir; mevcut iskelette bu davranış uygulanmamıştır. Aynı hedefte ortak implementasyon hem doğrudan derlenip hem static LIB'den alınarak duplicate symbol oluşturulmaz. Derleme ara çıktıları proje/toolchain/mimari/konfigürasyona özel tutulur; `src` içine yazılmaz.

DLL Runner ve LIB Runner aynı conformance senaryolarını ve örnek girişlerini çalıştırır. CLI parsing/formatlama katmanı yeniden kullanılabilir; hiçbir runner AES, hashing veya imza mantığını tekrar implement etmez. SDK DLL ve static SDK aynı süreçte birlikte kullanılacaksa context/handle'lar instance sınırını geçemez; ilk örnekler her süreçte tek bağlantı biçimi kullanır.

### 21.3 Runner ve EXE davranışı

- DLL Runner: DLL yolu, API/provider listesi, algoritma seçimi, dosya/string işlem senaryosu, callback/progress testi ve hata raporu.
- LIB Runner: aynı işlemler, build metadata'sı ve bağlı statik sağlayıcı listesi; provider DLL gerekmediği belirtilen profilde SDK DLL kaldırılarak doğrulama.
- CLI EXE: altı ana işlev, key yönetimi, batch/manifest, ilerleme, Ctrl+C iptali, insan tarafından okunabilir ve sürümlü JSON çıktı.
- Certificates CLI: `cert inspect`, `cert list`, `cert import`, `cert export`, `cert validate`, `cert selfsign`, `cert csr`; aynı senaryolar DLL/LIB Runner ve opsiyonel script binding'inde sunulur.
- SSL/TLS ve SSH CLI/runner: `tls connect`, test listener profili, `ssh exec`, `sftp upload/download/list`; hedef ve kimlik bilgileri açık girdidir. SSH server veya genel remote shell daemon ilk CLI kapsamı değildir.
- Binary çıktı stdout'a yazılabiliyorsa progress stderr'e gider. Binary veriye log karıştırılmaz.
- Parola/private key komut satırı argümanına zorlanmaz; güvenli prompt, uygulamanın sağladığı secret kaynağı veya açık key reference kullanılır.
- Başarı, geçersiz doğrulama, teknik hata, iptal ve kısmi batch sonucu için ayrı belgelenmiş exit code verilir.
- VCL görsel örneği ayrıca sunulur; kullanıcı GUI türünü seçmediği için ana EXE şimdilik console/CLI olarak tasarlanır.

### 21.4 Paket varyantları

Paket anahtarı: SDK version + compiler/toolset + architecture + Debug/Release + CRT/linkage. Örneğin MSVC x64 static paketi C++Builder Win32 static paketi yerine kullanılamaz. DLL runtime dosyası mimari başına paylaşılabilir; wrapper/import library hedef toolchain'e uygun hazırlanır.

Opsiyonel bağımlılık listesi her pakette açık bulunur. `BUILD_SHARED`, `BUILD_STATIC`, `BUILD_DLL_RUNNER`, `BUILD_LIB_RUNNER`, `BUILD_CLI`, `WITH_LUA`, `WITH_OPENPGP`, `WITH_OPENSSL`, `WITH_CRYPTOPP`, `WITH_BOTAN`, `WITH_CUSTOM` eşdeğeri build seçenekleri tanımlanır; native C++Builder projeleri aynı özellik profilini uygular.

### 21.5 Oluşturulan C++Builder proje iskeletleri

Kullanıcının isteğiyle `projects/cppbuilder` altında `All`, `AppBuilder`, `AppRunner`, `DllBuilder`, `DllRunner`, `LibBuilder`, `LibRunner` klasörleri oluşturuldu. Altı native `.cbproj` ve hepsini içeren `All/All.groupproj` bulunur. Ortak kaynak erişimi proje klasörlerinden `../../../src` olarak ayarlandı. Başlangıç kodları yalnız boş EXE/DLL giriş noktaları ve statik LIB placeholder fonksiyonudur; SDK implementasyonu veya runner bağlantıları eklenmedi.

Kurulu RAD Studio 37.0 ile Win32/Win64 Debug/Release dahil 24 hedef derlemesi başarılıdır. C++Builder 10 ve diğer sürümlerde uyumluluk henüz test edilmedi. Yerel kurulumda Windows SDK `windows.h` başlığı eksik bulundu; boş iskeletler bunu gerektirmez, gerçek Windows API implementasyonu öncesi kurulum doğrulanacaktır.

Kullanıcının sonraki isteğiyle yedi Visual Studio klasörü `projects/msvc` altına birlikte taşındı. `All/All.sln` ve tekil solution'ların göreli proje yolları korundu. Her iki toolchain'in proje klasöründen ortak kaynak yolu `../../../src` olur. MSVC projelerinde henüz ortak SDK kaynak/include referansı bulunmadığından taşıma için `.vcxproj` değişikliği gerekmedi; implementasyon eklenirken bu yollar kullanılacak.

## 22. Test ve kabul stratejisi

### 22.1 Kriptografi doğruluğu

- AES-GCM, SHA-2, HMAC, PBKDF2, RSA-PSS/OAEP ve ECDSA için yayımlanmış bilinen cevap vektörleri seçilir; kaynak ve profil test metadata'sında tutulur.
- Aynı sabit key/nonce/AAD ile cipher sonucu sağlayıcılar arasında karşılaştırılır.
- RSA-PSS ve ECDSA gibi rastgelelik içerebilen imzalarda aynı byte sonucu beklemek yerine çapraz verify yapılır.
- Yanlış key, bozuk tag, bozuk signature, değiştirilmiş AAD/header, sıfır/eksik veri ve sınır boyutları denenir.
- CNG ile üretilen envelope diğer sağlayıcıyla açılır; tersi de test edilir. Key ve signature format dönüşümleri ayrı vektörlerle doğrulanır.

### 22.2 I/O ve format güvenliği

- Boş dosya, 4 GiB üzeri dosya, chunk sınırlarının bir eksi/fazlası, non-seekable kaynak, kısa read/write.
- Disk dolması, erişim reddi, hedef çakışması, kaynak değişimi, iptal ve commit hatası.
- UTF-8/Türkçe adlar, uzun yollar, reparse point, case/normalization çakışması ve path traversal.
- Chunk tekrarı, sıra değişimi, başka mesajdan parça, eksik final, sonda fazla byte.
- Parser fuzzing: length overflow, dev KDF parametresi, bozuk encoding ve sıkıştırma bombası limitleri.
- Strict decryption başarısızsa çıktı commit edilmediği ve callback'lerin plaintext taşımadığı kontrol edilir.

### 22.3 ABI ve concurrency

- Hedef toolchain başlık derleme, DLL yükleme, export isimleri, calling convention, yapı hizalama, pointer/64-bit boyut testleri.
- Allocation/free sınırı, farklı CRT, handle kapanışı, provider lifetime ve callback context ömrü.
- Paralel işler, cancel/complete yarışları, UI dispatcher kapanışı, callback hata ve kuyruk sınırı.
- C++Builder VCL `TStream` ile MSVC stream adaptörünün aynı girdide aynı sonucu üretmesi.
- DLL Runner, LIB Runner ve CLI'ın aynı test corpus'unda aynı semantik sonucu vermesi; DLL ile şifrelenenin statik LIB ile çözülmesi ve tersinin doğrulanması.
- Statik CNG LIB Runner'ın SDK DLL bulunmadan çalışması; import LIB'in statik paketle karıştırılmadığının dependency kontrolü.
- Yanlış mimarili DLL, eksik export, uyumsuz ABI ve eksik opsiyonel provider durumlarında runner'ın kontrollü hata vermesi.

### 22.4 Performans ve kalite kapısı

Throughput, peak memory, ilk çağrı maliyeti, küçük mesaj gecikmesi, chunk boyutu ve worker sayısı ölçülür. Donanım ve Windows/provider sürümü rapora yazılır. Önceden kanıtsız hız hedefi verilmez.

Yayın kapısı: hedef matriste ABI testleri, algoritma vektörleri, format negatif testleri, yüksek önemde açık hata olmaması, dokümantasyon ve örneklerin çalışması. Native crypto kullanımı güvenlik incelemesinin yerine geçmez; özellikle format, anahtar, nonce ve bellek sınırları incelenir.

## 23. Uygulama aşamaları ve teslimatlar

### 23.0 Geliştirme önceliği: Microsoft Visual Studio

Kodlama ve ilk tasarım prototipleri Microsoft Visual Studio ile başlayacaktır. Ana geliştirme solution'ı `projects/msvc/All/All.sln`, ortak üretim kodlarının kökü ise `src` olacaktır. `projects/cppbuilder` altındaki C++Builder projeleri bu aşamada uyumluluk iskeleti olarak korunacak; ortak API ve ABI olgunlaştıkça aynı `src` kaynaklarıyla derlenecektir.

İlk MSVC çalışma sırası:

1. `src/include/aycrypto/c` altında sürümlü C ABI başlıklarını ve `src/core` altında hata, sonuç, buffer, handle ve yaşam döngüsü çekirdeğini oluşturmak.
2. `DllBuilder` ile Windows DLL export katmanını, `LibBuilder` ile gerçek statik kütüphane hedefini aynı `src` kaynaklarından üretmek.
3. `AppBuilder`ı CryptoAPI komut satırı/örnek uygulaması olarak ortak API'ye bağlamak.
4. `DllRunner`ı DLL'i runtime yükleyen ABI ve API doğrulama programı, `LibRunner`ı statik LIB'e linklenen conformance programı olarak bağlamak.
5. `AppRunner`ı AppBuilder çıktısını ayrı süreçte çalıştıran test host'u olarak tasarlamak; stdout, stderr, exit code, timeout ve iptal davranışını doğrulamak.
6. Windows CNG ile önce `RandomGenerator` ve `Hasher`, ardından AES-GCM `Encryptor`/`Decryptor` servislerini eklemek.
7. Her MSVC yapılandırmasında Win32/x64 ve Debug/Release derlemelerini doğruladıktan sonra C++Builder derleme geçişine başlamak.

Bu aşamada mevcut Visual Studio giriş dosyaları başlangıç şablonlarıdır; kriptografi mantığı proje klasörlerine yazılmayacaktır. `DllBuilder` ve `LibBuilder` ortak `.cpp` dosyalarını proje referanslarıyla derleyecek, runner'lar servisleri yeniden uygulamayacaktır. İlk kabul ölçütü, DLL ve statik LIB üzerinden aynı CNG test vektörlerinin ve aynı hata sözleşmesinin elde edilmesidir.

| Faz | Kapsam | Teslimat ve çıkış kriteri |
| --- | --- | --- |
| 0 — Tasarımın kesinleşmesi | IDE/OS matrisi, DLL kararı, API taslağı, threat model | Karar kaydı; kodlama başlamadan tasarım üzerinde mutabakat |
| 1 — Uyumluluk iskeleti | C ABI, ortak kaynak/wrapper, DLL + gerçek static LIB, runner iskeletleri | MSVC ve en eski hedef C++Builder'da iki bağlantı biçimi, alloc ve callback prototipi çalışır |
| 2 — CNG temelleri | RNG, SHA-2, HMAC, KDF, ephemeral key | Bilinen vektörler, byte/string ve temel stream örnekleri geçer |
| 3 — Encryption/Decryption | AES-GCM, envelope şartnamesi, staging, file/stream | Tag/nonce/format negatif testleri ve büyük dosya testleri geçer |
| 4 — Signing/Verification | RSA-PSS, ECDSA, key formats, detached signature | Geçerli/geçersiz imza, encoding ve digest sözleşmeleri doğrulanır |
| 5 — Files/folders ve events | Batch, manifest, async, cancellation, VCL adaptörü | Bütün veri biçimleri, UI lifetime ve kısmi hata örnekleri çalışır |
| 6 — Anahtar saklama ve v1 sertleştirme | NCrypt, DPAPI, limitler, tam DLL/LIB Runner ve CLI, paketleme | Altı dağıtım/kullanım biçimi ve iki bağlantı modelinin kabul raporu tamamlanır |
| 6A — Certificates | X.509/PEM/DER/PFX, Windows depoları, key bağı, zincir/revocation, self-signed ve CSR | Bölüm 25 kabul testleri; DLL/static LIB, runner ve CLI sertifika örnekleri geçer; v1 sertifika kapsamı tamamlanır |
| 7 — Harici sağlayıcılar | Önce OpenSSL, ardından Crypto++ ve Botan | Her ek sağlayıcı için aynı conformance suite ve çapraz veri testleri geçer |
| 8 — OpenPGP | RNP/GPGME kararı ve protocol adaptörü | Seçilen dış uygulamayla encrypt/decrypt/sign/verify testleri geçer |
| 9 — Script | Lua binding, izinler, kotalar, event dispatch | Güvenilir script use case'leri ve limit testleri geçer |
| 10 — CustomProvider | Kendi standart algoritma implementasyonlarımız | Vektör, çapraz test, fuzz ve güvenlik değerlendirmesi; ayrı deneysel yayın |
| 11 — SSL/TLS | Network transport, Schannel client/server, certificate policy, mTLS | Bölüm 26 testleri, Windows ve toolchain matrisi, DLL/LIB/CLI örnekleri |
| 12 — SSH | libssh2 client, host key doğrulama, authentication, exec ve SFTP | Bölüm 27 testleri ve gerçek test sunucusuyla interoperability |
| 13 — Protokol genişlemeleri | OpenSSL TLS backend; ihtiyaç halinde forwarding, SSH server/libssh | Seçilen capability ve dağıtım kombinasyonları ayrı doğrulanır |

Fazlar takvim taahhüdü değildir; süre API/format kararları ve erişilebilir test ortamları belli olduktan sonra tahmin edilir. Sağlayıcı arayüzünün gerçekten genel olduğu Faz 7'de ikinci motorla doğrulanmadan kararlı plugin ABI ilan edilmez; ilk sürümde plugin sözleşmesi preview olarak işaretlenebilir.

## 24. Tasarım kararları ve açık noktalar

| Konu | Bu taslaktaki karar/öneri | Durum |
| --- | --- | --- |
| SDK/proje adı | `CryptoAPI` | Kullanıcı tarafından seçildi |
| C++ adlandırma | `aycrypto` namespace, `aycrypto::CryptoApi` facade | Önceki namespace önerisiyle uyumlu tasarım |
| C ABI adlandırma | `aycrypto_` fonksiyon/tip öneki | Namespace dışındaki C sembollerini ayırma |
| Ortak kaynak konumu | Kök `src`; mevcut altı klasör Visual Studio projeleri | Kullanıcı tarafından belirlendi |
| İlk geliştirme toolchain'i | Microsoft Visual Studio 2022 ve üzeri | Kullanıcı tarafından belirlendi; C++Builder sonraki uyumluluk doğrulaması |
| MSVC solution | `projects/msvc/All/All.sln` | İlk kodlama ve tasarım giriş noktası |
| İlk servis sırası | RandomNumber → Hashing → Encryption/Decryption | CNG ile dikey dilim yaklaşımı |
| C++Builder | 10 ve üzeri; classic/Clang ayrı hedefler | Kullanıcı gereksinimi |
| Visual Studio | 2022 ve üzeri | Kullanıcı tarafından netleştirildi |
| İşletim sistemi | Şimdilik Windows; minimum sürüm ayrıca belirlenecek | Windows kapsamı kesin, alt sürüm sınırı açık |
| Kullanım ve dağıtım | C++ sınıfları + DLL + DLL Runner + gerçek static LIB + LIB Runner + EXE | Kullanıcının eklediği zorunlu kapsam |
| Runner anlamı | DLL Runner runtime loader; LIB Runner statik bağlı örnek/test EXE | Kullanıcı ifadesine ilişkin tasarım yorumu |
| EXE arayüzü | Console/CLI; ayrı VCL örneği | Öneri |
| Ortak çekirdek dili | Classic BCC32 static desteği için C++03 uyumlu alt küme | Genişleyen dağıtım kapsamına göre mimari karar |
| Template kapsamı | İstemci adaptörleri, traits ve typed sonuçlar | Öneri |
| İlk motor | Windows CNG | Kullanıcı gereksinimi |
| Certificates | X.509, depolar, zincir doğrulama, self-signed ve CSR; önce Windows Crypt32/CertEnroll | Kullanıcının eklediği kapsam; bölüm 25 |
| SSL/TLS | Önce Schannel; TLS 1.2/1.3 capability, client/server ve mTLS | Kullanıcının eklediği kapsam; bölüm 26 |
| SSH | SSH2 client ve SFTP; ilk motor libssh2, server ayrı genişleme | Kullanıcının eklediği başlık için önerilen kapsam; bölüm 27 |
| İlk güvenli profil | AES-GCM, SHA-2, RSA-PSS/ECDSA, sistem RNG | Öneri |
| Stream çözme | Strict staging varsayılan | Öneri |
| Klasör anlamı | Dosya batch'i + canonical manifest | Öneri |
| Script | Opsiyonel Lua | Öneri; ilk çekirdek için zorunlu bağımlılık değil |
| OpenPGP motoru | RNP değerlendirmesi, GPGME alternatif | İlgili fazda seçilecek |
| Custom algoritmalar | Ayrı Experimental provider | Kullanıcı genişleme gereksinimi |
| Destek garantisi | Test edilen sürüm/mimari/politika matrisi | Yayın kabul ölçütü |

Bir sonraki tasarım oturumunda minimum Windows sürümü, ortak sınıf isimleri ve servislerin public metotları kesinleştirilecek. Ardından C ABI, envelope formatı ve protokol servislerinin sözleşmeleri ayrı ayrıntılı şartnamelere dönüştürülecek. Kullanıcının tasarım tamamlandıktan sonra kodlama isteği doğrultusunda bu belge aşamasında uygulama dosyaları oluşturulmayacak.

## 25. Certificates

### 25.1 Amaç ve sınırlar

Sertifika işlemleri bağımsız C++ sınıflarıyla ve `aycrypto::CryptoApi` nesnesinin `certificates()` metodu üzerinden kullanılacak. İlk hedef X.509 v3 sertifikalarıdır. Sertifika bir public key'yi kimlik ve kullanım bilgilerine bağlar; private key ayrı nesnedir. Bir sertifikanın okunması, kendi imzasının doğrulanması veya self-signed olması uygulama tarafından güvenilir kabul edildiği anlamına gelmez.

Kapsam: sertifika inceleme, oluşturma, içe/dışa aktarma, arama, Windows sertifika depoları, anahtar eşleştirme, CSR oluşturma ve politika tabanlı zincir doğrulaması. Tam CA sunucusu, otomatik ACME/SCEP/EST enrollment, CRL/OCSP sunucusu işletimi ve timestamp otoritesi sonraki bağımsız entegrasyonlardır. OpenPGP sertifikaları/keyring'i mevcut `OpenPgpService` kapsamındadır; X.509 ile aynı parser'a verilmez.

### 25.2 Sınıflar ve API

| Sınıf / sözleşme | Sorumluluk |
| --- | --- |
| `Certificate` / `CertificateHandle` | Değişmez sertifika içeriği ve opaque referans |
| `CertificateInfo` | Subject, issuer, serial, SAN, validity, public key, signature algorithm, KU/EKU ve extension bilgileri |
| `CertificateManager` | Yükleme, arama, aktarım ve alt servislerin koordinasyonu |
| `CertificateStore` / `ICertificateStore` | Memory, CurrentUser, LocalMachine veya uygulama deposu |
| `CertificateBuilder` | Açık subject/SAN, kullanım amacı, süre ve anahtarla self-signed sertifika oluşturma |
| `CertificateRequestBuilder` | PKCS#10 CSR oluşturma; talep imzasını anahtarla üretme |
| `CertificateChain` / `CertificateValidator` | Zincir oluşturma ve seçilen güven politikasını değerlendirme |
| `CertificateValidationPolicy` | Trust anchor, zaman, kullanım amacı, gerekiyorsa isim ve revocation/network politikası |
| `CertificateValidationResult` | Genel karar, zincir ve kontrol başına sonuç/açıklama |
| `ICertificateProvider` | Parser, codec ve sertifika yeteneklerinin sağlayıcı sözleşmesi |

`Certificate` private key sahiplenmez; ilişki ayrı `KeyHandle` ile kurulur. Windows certificate context ve store handle'ları provider içinde RAII ile yönetilir; DLL sınırında Windows/COM nesneleri paylaşılmaz. Diğer servislerle aynı C ABI, caller-owned buffer ve SDK-owned output kuralları uygulanır. Template'ler kaynak/sink adaptörlerini kolaylaştırır; certificate parsing mantığını çoğaltmaz.

### 25.3 Formatlar ve veri kaynakları

- DER ve PEM X.509 okuma/yazma; `.cer`/`.crt` uzantısı encoding garantisi değildir.
- PKCS#12 `.pfx`/`.p12`: sertifika zinciri ve mevcutsa private key aktarımı. Parola `PasswordSecret` veya credential callback ile alınır; loglanmaz.
- PKCS#10 CSR: DER/PEM çıktı; CSR üretmek CA'nın sertifika verdiği anlamına gelmez.
- Birden çok PEM sertifika ve PKCS#7 certificate bundle ayrı format/capability olarak ele alınır; bundle okumak CMS mesaj imzası doğrulaması sağlamaz.
- File/files, stream/streams ve byte kaynakları desteklenir; string için PEM veya açık Base64 encoding gerekir. Folder/folders, filtreli sertifika dosyası batch'i olarak yorumlanır.
- ASN.1 uzunluk/derinlik, sertifika sayısı, toplam boyut ve PFX KDF maliyeti sınırlanır. Genel I/O stream desteklese de parser'ın sınırlı boyuttaki sertifikayı belleğe alabileceği belgelenir.

PFX içinde birden fazla kimlik bulunabilir; ilk private key sessizce seçilmez. Sertifika-public key eşleşmesi doğrulanır, kimlik seçimi açık filtreyle yapılır. Non-exportable private key bulunan kimlikte public sertifika export edilebilir; private key export isteği izin yoksa hata verir.

### 25.4 İlk Windows implementasyonu

Kriptografik primitive'ler CNG'de kalır; sertifika/depo/zincir işlemleri `Crypt32` Certificate API'leriyle uygulanır. `CertOpenStore` farklı depo türleri için başlangıç noktasıdır. [Microsoft CertOpenStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore)

PFX aktarımında `PFXImportCertStore` kullanılabilir. API bayrakları anahtar kalıcılığı ve sağlayıcı tercihine etki ettiğinden `load/inspect` ile kalıcı `importToStore` ayrı işlemler olur. Salt inceleme disk üzerinde anahtar/depo değişikliği yapmamalı; sağlayıcı bunu sağlayamıyorsa yan etkisiz yükleme isteğini reddeder. [Microsoft PFXImportCertStore](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-pfximportcertstore)

Sertifikaya bağlı private key `CryptAcquireCertificatePrivateKey` üzerinden edinilir. Dönen anahtar türü ve sahiplik bayrağına uyulur; CNG `NCrypt` handle'ı ile legacy CSP handle'ı karıştırılmaz. İlk CNG profili desteklemediği legacy key türünü açık hata olarak raporlar. [Microsoft private key edinme API'si](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecertificateprivatekey)

CSR oluşturma için CertEnroll adaptörü değerlendirilir. COM initialization, apartment, hata ve lifetime yönetimi adaptör içinde tutulur; uygulamanın mevcut COM apartment modeli değiştirilmez. Gerekirse SDK'nın sahip olduğu uygun worker kullanılır. [Microsoft Certificate Enrollment API](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/certenroll-portal)

### 25.5 Sertifika oluşturma ve anahtar bağı

Self-signed oluşturma açık builder seçenekleriyle çalışır: subject, SAN, validity, public key, signature suite, Basic Constraints, Key Usage ve Extended Key Usage. Varsayılan kullanım end-entity'dir; CA yetkisi kendiliğinden verilmez. Serial pozitif, sıfır olmayan ve profil sınırlarına uygun CSPRNG üretimiyle oluşturulur; süre ve extension tutarlılığı doğrulanır.

Anahtar üretimi `KeyManager` tarafından yapılır. Var olan key ile sertifika/CSR oluşturma desteklenir; export gerektirmeyen KSP anahtarı capability uygunsa doğrudan kullanılabilir. Self-signed sertifika oluşturma Windows Root deposuna kurulum yapmaz.

CA'dan gelen sertifika CSR'nin beklenen anahtarıyla eşleştirilir; public key, kimlik ve kullanım politikası kontrolünden sonra explicit install/import çağrısıyla kaydedilir. Sertifika yenileme ve key rotation ayrı seçimlerdir; eski key ve sertifikalar örtük silinmez.

### 25.6 Zincir, güven ve revocation doğrulaması

Zincir oluşturma, güven kararı ve mesaj imzası doğrulaması ayrı aşamalardır. Windows başlangıcında `CertGetCertificateChain` ile zincir/revocation değerlendirmesi, `CertVerifyCertificateChainPolicy` ile seçilen amaç politikası uygulanır. API çağrısının başarılı dönmesi tek başına sertifikanın geçerli olduğu anlamına gelmez; trust status ve policy hata alanları okunur. [Zincir oluşturma](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain), [Zincir politikası](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certverifycertificatechainpolicy)

Kontroller: leaf ve issuer imzaları, validity zamanı, güvenilen kök, Basic Constraints/path length, Key Usage/EKU, kritik extension'lar ve sağlayıcının desteklediği name constraints. TLS kimliği profili seçilirse beklenen DNS/IP adı açık parametredir; yalnız subject metni karşılaştırılmaz. Bu profil TLS bağlantısı kurma yeteneği anlamına gelmez.

Trust store seçimi `SystemTrust` veya açık `ApplicationTrust` olur. Uygulama trust anchor'ları sistem kökleriyle ancak açık politika isterse birleştirilir. Sertifikayla birlikte gelen self-signed root otomatik güven kaynağı yapılmaz.

Revocation seçenekleri `Required`, `BestEffort`, `Disabled`; ağ seçenekleri `Offline`, `CacheOnly`, `Online` olarak ayrı tanımlanır. Varsayılan güven doğrulama profili `Required + CacheOnly` önerisidir: yeterli güncel kanıt yoksa `Indeterminate` döner ve güven gerektiren çağrı başarılı sayılmaz. Online erişim açık etkinleştirilir; AIA/CRL/OCSP erişimi, timeout, cache yaşı ve kaynak limitleri belirlenir. URL/kaynak kısıtlarını platform motorunun uygulayamadığı özel politika capability hatası verir.

Sonuçta en az `Trusted`, `Untrusted`, `Indeterminate` genel kararı ve ayrı süre/kullanım/isim/revocation alanları bulunur. Revocation `Good`, `Revoked`, `Unknown`, `NotChecked` ayrımını korur; `BestEffort` eksik kanıtı rapordan kaldırmaz. Teknik doğrulama hatası da ayrı durum kodudur. Değerlendirme zamanı ve politika kimliği rapora yazılır. Geçmiş tarih vermek geçmişteki iptal durumunu veya güvenilir imza zamanını tek başına kanıtlamaz; timestamp/uzun dönem doğrulaması ayrı genişlemedir.

### 25.7 Depolar, event'ler ve entegrasyon

Depolar varsayılan salt okunur açılır. Arama filtreleri fingerprint, issuer+serial, subject, EKU ve private key varlığını içerebilir; subject benzersiz kimlik sayılmaz. Sertifika fingerprint'i algoritması belirtilmiş DER digest'idir, güven kanıtı değildir.

Store yazma, silme, Root'a ekleme ve private key silme ayrı explicit API işlemleridir. LocalMachine yazma izinleri açık hata olarak döner. Sertifika silme private key silmeyle birleştirilmez. GUI onayı SDK tarafından kendiliğinden açılmaz; uygulama kendi yetkilendirme politikasını uygular.

`Signer`, sertifikaya bağlı key ile çalışır; `Verifier` sertifika public key'sinden imzayı kontrol eder ve istenirse certificate trust sonucunu ayrıca ekler. Şifrelemede yalnız key algoritması ve KU/EKU politikası uyumlu sertifika alıcı olarak kullanılabilir; her sertifika şifreleme anahtarı sayılmaz.

Batch inceleme/doğrulama mevcut operation/item event'lerini kullanır. Zincir/ağ işlemlerinde kesin yüzde yoksa indeterminate progress verilir. Distinguished name gibi kişisel bilgiler log politikasına tabidir. Lua binding, runner ve CLI aynı sertifika servislerini kullanır; Windows depolarına yazma script politikasında ayrı izin gerektirir.

### 25.8 Diğer sağlayıcılar ve kabul testleri

OpenSSL/Botan sertifika codec ve doğrulama adaptörleri sonraki sağlayıcı fazında değerlendirilecek; Crypto++ veya CustomProvider'a tam PKI desteği otomatik atfedilmeyecek. Kripto sağlayıcısı ile sertifika trust backend'i ayrı seçilebilir. Capability matrisi format, store, private key binding, chain engine ve revocation kapsamını bildirir. Aynı trust anchor ve doğrulama girdileri olmadan iki motorun aynı güven kararını vereceği varsayılmaz.

Kabul testleri:

- DER/PEM dönüşümünde sertifika içeriği korunması; yanlış/bozuk format ve sınır aşımının reddi.
- PFX yanlış parola, çoklu kimlik, key eşleşmezliği, export yasağı ve yan etkisiz inspect kontrolü.
- Süresi geçmiş/henüz başlamamış, eksik intermediate, güvenilmeyen root, bozuk imza, yanlış KU/EKU/isim ve bilinmeyen kritik extension.
- Revoked, stale/ulaşılamayan revocation verisi, cache-only ve online timeout; `Unknown` durumunun başarıya çevrilmemesi.
- Trust kontrolünün yalnız API dönüş boolean'ına bakmaması; imza geçerli fakat sertifika güvenilmez senaryosu.
- Self-signed ve CSR üretimi, CSR imzası/public key eşleşmesi, Root deposuna örtük yazılmaması.
- Gerçek makine güven depolarını değiştirmeyen memory/test store fixture'ları; gerekli kalıcı store testleri izole test makinesinde.
- DLL/LIB Runner çapraz format kullanımı, x86/x64 lifetime, callback/iptal ve VCL entegrasyonu.

## 26. SSL / TLS

### 26.1 Amaç ve protokol kapsamı

Başlık yaygın “SSL” adını içerir; yeni bağlantılar için tasarlanan protokol TLS'dir. SSL 2.0/3.0 ve TLS 1.0/1.1 varsayılan veya otomatik fallback olmayacak. İlk hedef TLS 1.2 ve sağlayıcı/Windows desteği varsa TLS 1.3'tür. İstenen minimum sürüm yoksa açık hata verilir; zayıf protokole sessiz geçiş yapılmaz.

Windows başlangıcında Schannel/SSPI, sonraki alternatif olarak OpenSSL `libssl` kullanılacak. Schannel TLS 1.3 desteği Windows 11/Windows Server 2022 ve üzerindeki platformlarla ilişkilidir; IDE sürümü TLS desteğini belirlemez. Bu, Windows çalışma sürümünü capability matrisinde ayrıca tutmamızın nedenidir. [Microsoft Schannel genel bakış](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-ssl-schannel-ssp-overview), [Schannel protokol desteği](https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-)

TLS bir bağlantı protokolüdür. `Encryptor` tarafından üretilen dosya envelope'u ile TLS record'ları birbirinin yerine kullanılmaz. HTTP/HTTPS istemcisinin tüm davranışları, WebSocket, QUIC ve DTLS ilk TLS servis kapsamına dahil değildir; üst protokol veya sonraki modül olarak değerlendirilir.

### 26.2 Sınıflar ve sağlayıcı sınırı

| Sınıf / sözleşme | Sorumluluk |
| --- | --- |
| `TlsService` / `ITlsProvider` | Provider seçimi, capability ve context üretimi |
| `TlsContext` / `TlsOptions` | Değişmez protokol, kimlik ve güven politikası |
| `TlsClient` / `TlsServer` | İstemci bağlantısı ve kabul edilen transport için sunucu handshake'i |
| `TlsSession` / `TlsStream` | Handshake, read/write, shutdown ve oturum bilgisi |
| `TlsPeerInfo` | Peer sertifikası, chain sonucu, negotiated protocol/cipher/ALPN |
| `INetworkTransport` | Duplex read/write, readiness, timeout ve close; ilk adaptör Winsock |

`ITlsProvider` küçük state-machine sözleşmesi sunar; DLL sınırında sürümlü C tablo ve opaque handle kullanılır. SSPI context, `SSL*`, socket sarmalayıcıları ve C++ exception dış ABI'ye çıkmaz. Harici transport sahipliği açıkça borrowed/owned olarak seçilir. `TlsServer` bir bağlantı oturumunu yönetir; listener lifecycle ve bağlantı limitleri ayrı network katmanındadır.

TLS motoru kendi protocol state'ini ve trafik anahtarlarını yönetir. Her record için genel `Encryptor` çağrısı yapılarak TLS yeniden implement edilmez. Genel crypto provider seçimi TLS motorunu kendiliğinden değiştirmez.

### 26.3 Sertifika, kimlik ve politika

- Client, beklenen server DNS/IP kimliğini bağlantı adresinden ayrı ve açık alır; SNI uygun DNS adıyla ayarlanır. Hostname doğrulaması kapalı varsayılan yoktur.
- Sunucu sertifikasının zinciri, süre, serverAuth kullanım amacı ve beklenen isim denetlenir. `CertificateValidationPolicy` ile bölüm 25'in trust/revocation kuralları uygulanır.
- Sunucu kendi certificate + private key kimliğini alır; mTLS profilinde client certificate zorunluluğu ve clientAuth politikası belirlenir.
- Peer doğrulaması tamamlanmadan uygulama katmanına başarı veya application data erişimi verilmez. Sunucunun mTLS istemci kimliğini hangi işlem için yetkilendireceği uygulamaya aittir.
- Pinning isteğe bağlı ek politikadır: sertifika veya SPKI digest türü, rotasyon ve normal trust kontrolleriyle birleşimi açıkça tanımlanır.
- Schannel için Windows certificate/KSP bağı kullanılır. OpenSSL'e non-exportable Windows private key aktarımı otomatik destek sayılmaz; uygun köprü yoksa capability hatası verilir.
- Protokol aralığı, cipher politikası ve ALPN istekleri açık konfigürasyondur. Uygulanamayan zorunlu kısıt sessizce yok sayılmaz; işletim sistemi registry ayarları SDK tarafından değiştirilmez.

### 26.4 Akış, olaylar ve bağlantı ömrü

Durumlar: Created → Connecting/Accepted → Handshaking → PeerValidated → Open → Closing → Closed; Failed/Cancelled terminal dallarıdır. TCP bağlantısı kurulması TLS handshake başarısı sayılmaz.

Kısa socket read/write, birden fazla record, eksik handshake girdisi ve buffer'da kalan şifreli veri doğru ele alınır. Nonblocking motorun `WantRead/WantWrite` ihtiyacı transport readiness'e çevrilir; busy loop yapılmaz. Session state çağrıları serialize edilir; duplex kullanım yalnız tanımlı yürütücü üzerinden sunulur.

Connect, handshake, read, write, idle ve shutdown timeout'ları ayrı tanımlanır. Yazma, verinin peer uygulaması tarafından işlendiğini garanti etmez. Bounded buffer/backpressure, iptal ve bağlantı sayısı limitleri uygulanır. TLS kapanış bildirimi ile beklenmedik transport EOF ayrılır; eksik veri üst protokole başarı diye iletilmez.

TLS 1.3 early data/0-RTT ilk sürümde kapalıdır. Session resumption sonraki optimizasyondur; ticket/cache sırları, kimlik ve politika değişimi birlikte ele alınmadan açılmaz. TLS record katmanının bütünlüğü uygulama mesajının eksiksiz alındığını tek başına garanti etmez; uzunluk/framing üst protokole aittir.

Event'ler mevcut operation context üzerinden connect, handshake, peer validation ve transfer phase'lerini bildirir. Transfer progress byte cinsindedir; bilinmeyen toplam için yüzde verilmez. Trafik anahtarları, credential ve uygulama payload'ı event/log'a konmaz.

File/files/folder/folders TLS bağlantısı üzerinden ancak tanımlı bir üst aktarım protokolüyle gönderilir. TLS modülü doğrudan byte/string/duplex stream sunar; “TLS folder gönder” çağrısı dosya isimleri ve sınırları için protokol olmadan tasarlanmaz. Böyle bir gereksinim sonraki `TransferService` veya SFTP ile karşılanır.

### 26.5 Dağıtım ve kabul testleri

Schannel adaptörü DLL ve toolchain'e özel gerçek static LIB içinde sunulabilir; Windows sistem bağımlılıkları sürer. OpenSSL TLS modülü ayrı seçilir; `libcrypto` entegrasyonu tek başına TLS desteği değildir. [OpenSSL libssl](https://docs.openssl.org/3.0/man7/ssl/)

Testler: TLS 1.2/1.3 capability, uyumsuz minimum sürüm, geçerli/geçersiz hostname, untrusted/expired/revoked sertifika, mTLS eksik/yanlış client kimliği, yanlış key bağı, ALPN uyuşmazlığı, parçalı handshake, kısa write, timeout/iptal, ani EOF ve graceful shutdown. Schannel–OpenSSL istemci/sunucu çapraz testleri yapılır; x86/x64 DLL/LIB Runner ve VCL callback yaşam süresi doğrulanır. Test kökleri sistem Root deposuna örtük kurulmaz.

## 27. SSH

### 27.1 Amaç ve ilk kapsam

SSH, TLS'den bağımsız protokol ve güven modelidir. İlk hedef SSH2 istemci bağlantısı, server host key doğrulama, public key/parola authentication, command/session kanalları ve SFTP'dir. SSH1 desteklenmez. Interactive shell/PTY, agent, port forwarding ve SSH server sonraki açık capability'ler olarak planlanır.

İlk motor adayı `libssh2`'dir; proje SSH2 istemci C API'si sunar. Sunucu gereksinimi için client/server destekleyen `libssh` ayrıca değerlendirilir. [libssh2](https://libssh2.org/), [libssh API](https://api.libssh.org/stable/index.html)

Windows'a öncelik verilmesi SSH protokolünün BCrypt veya Schannel ile hazır sağlandığı anlamına gelmez. SSH ayrı bir protokol bağımlılığı gerektirir. Windows OpenSSH `ssh.exe`/`sftp.exe` programları varsa bunları gizlice çalıştırmak kütüphane backend'i yerine kullanılmaz; harici süreç adaptörü ancak ayrı özellik olarak tasarlanır. İlk Windows kripto çekirdeği SSH modülü olmadan da çalışır.

### 27.2 Sınıflar ve API

| Sınıf / sözleşme | Sorumluluk |
| --- | --- |
| `SshService` / `ISshProvider` | Provider, capability ve istemci üretimi |
| `SshClient` / `SshSession` | Connect, key exchange, host identity, authenticate ve close |
| `SshOptions` / `SshAuthentication` | Hedef/port, algoritma, timeout ve credential seçenekleri |
| `KnownHostsStore` / `HostKeyPolicy` | Host+port anahtar eşleşmesi, pinning ve kayıt politikası |
| `SshChannel` / `RemoteCommandResult` | exec/shell kanalı, stdin/stdout/stderr ve exit bilgisi |
| `SftpClient` / `SftpFile` | Dosya açma, read/write, stat, list, rename ve aktarım |
| `SftpTransferOptions` | Overwrite, staging, metadata ve resume politikası |

C++ sınıfları ortak ABI üzerinden çağırılır; `LIBSSH2_SESSION*` veya sağlayıcıya özel nesneler dışarı verilmez. Session/kanal/SFTP handle lifetime sırası korunur. SSH session iç çağrıları serialize edilir; birçok kanal bulunması sağlayıcı nesnesine eşzamanlı kontrolsüz erişim izni vermez.

### 27.3 Host key ve kullanıcı kimlik doğrulaması

Host key kontrolü authentication credential gönderilmeden önce yapılır. Varsayılan `StrictKnownHosts`: bilinmeyen veya değişmiş host key bağlantıyı reddeder. İsteğe bağlı explicit pin veya uygulamanın karar verdiği ilk kullanım kaydı sunulur; sessiz “accept all” yoktur. Host adı, port ve anahtar algoritması kaydın parçasıdır; fingerprint formatı/algoritması açık tanımlanır.

OpenSSH host/user certificates, X.509 sertifikaları değildir. Bölüm 25 `CertificateValidator` ile otomatik doğrulanmaz; desteklenirse ayrı SSH certificate/CA politikası ve provider capability gerekir.

Authentication sırası açık seçeneklerden oluşur: public key, parola, gerektiğinde keyboard-interactive ve daha sonra agent. Private key formatı ve passphrase kaynağı belirtilir. Keyboard-interactive birden fazla tur/challenge içerebilir; echo/no-echo ve iptal sözleşmesiyle ayrı credential callback kullanılır. Password/passphrase event log'larına veya komut satırına zorlanmaz.

Host key algorithm, key exchange, cipher, MAC ve user signature algoritmaları ayrı yeteneklerdir. RSA key bulunması SHA-1 tabanlı `ssh-rsa` signature kullanımını zorunlu kılmaz; izin verilen signature profili ayrıca seçilir. Zorunlu politika uygulanamıyorsa bağlantı reddedilir. Windows NCrypt non-exportable key veya agent entegrasyonu sağlayıcı desteklemeden vaat edilmez.

### 27.4 Command, stream ve dosya işlemleri

`execute(command)` SSH exec isteği gönderir; sunucu komutu kendi kurallarıyla yorumlar. API bunun güvenli bir argv aktarımı olduğunu iddia etmez; shell escaping hedef ortama bağlıdır. Komut otomatik tekrar çalıştırılmaz. Bağlantı koparsa komutun çalışıp çalışmadığı belirsiz olabilir; `RemoteOutcomeUnknown` ile raporlanır.

stdin/stdout/stderr ayrı akışlardır. stdout ve stderr birlikte boşaltılır; yalnız birini okuyarak deadlock oluşturulmaz. Çıktı limitli buffer veya streaming sink'e gider. Remote exit status, signal, kanal EOF ve transport hatası ayrı sonuç alanlarıdır. Eksik exit status sıfır olarak uydurulmaz. İptal kanalın kapanmasını talep eder; remote prosesin kesin öldüğünü garanti etmez.

SFTP ilk dosya aktarım yöntemidir; SCP varsayılan değildir. Byte/string/stream upload/download adaptörleri, files batch'i ve folder recursive transfer planı sunulur. SFTP, FTP-over-TLS/FTPS ile karıştırılmaz.

Dosya transferi kuralları:

- Remote path, yerel Windows path'ten ayrı türdür; `std::filesystem`/Win32 normalizasyonu uzaktaki yola körlemesine uygulanmaz.
- Recursive download yerel hedef kökü dışına çıkamaz; symlink/reparse, özel ad ve ad çakışmaları denetlenir.
- Upload mümkünse remote geçici dosyaya yapılır; başarılı kapanıştan sonra rename ile commit edilir. Atomic overwrite/rename garantisi sunucu capability'sine bağlıdır.
- Download yerel staging + commit kullanır; aktarımın bitmesi yerel flush/commit başarısını içerir.
- Varsayılan overwrite ve resume kapalıdır. Resume sonradan eklenirse kaynak kimliği, offset ve değişim doğrulaması gerekir; yalnız dosya boyutu yeterli sayılmaz.
- Klasör genelinde atomiklik yoktur; izin/time metadata best-effort sonuçları ayrı raporlanır. ACL ve Windows ADS tam korunmuş sayılmaz.
- SSH transport bütünlüğü sağlar; uzakta kalıcı depolama veya bağımsız içerik hash doğrulaması ancak ek protokol/özellikle garanti edilebilir.

### 27.5 Ağ, callback ve hata modeli

Durumlar: Created → Connecting → KeyExchange → HostVerified → Authenticating → Ready → Closing → Closed; Failed/Cancelled dalları bulunur. `HostVerified` ile kullanıcı authentication başarısı ayrı olaylardır.

Network transport TLS ile ortak duplex sözleşmeyi kullanabilir; TLS üzerinden SSH tünellemesi otomatik varsayılmaz. Nonblocking `WouldBlock/EAGAIN` motorun beklediği read/write readiness'e bağlanır. Connect/auth/channel/read/write timeout'ları, keepalive, backpressure ve buffer limitleri ayrı ayarlanır. Keepalive remote komutun tamamlandığını göstermez.

SFTP byte/öğe progress'i ve phase event'leri mevcut dispatcher'dan geçer. Credential/host key karar callback'leri gözlem event'lerinden ayrıdır; timeout ve lifetime yönetimi vardır. Hatalar `HostKeyUnknown`, `HostKeyMismatch`, `AuthenticationFailed`, `AlgorithmNegotiationFailed`, `ChannelOpenFailed`, `RemotePermissionDenied`, `RemoteOutcomeUnknown` gibi açık kategorilerle mevcut hata modeline bağlanır.

### 27.6 Dağıtım, genişleme ve kabul testleri

libssh2 ve onun crypto backend'i sürüm/toolchain bazında pinlenir. Classic C++Builder için ortak DLL sınırı kullanılabilir; tam statik SSH ancak bağımlılıkları o toolchain'de derlenip doğrulanınca ilan edilir. libssh2 dağıtım/lisans bildirimi ve opsiyonel libssh bağımlılığı ayrı paket kayıtlarına alınır. [libssh2 projesi](https://github.com/libssh2/libssh2)

Port forwarding eklenirse bind adresi/port, hedef izinleri ve bağlantı sayısı açık politikadır. SSH server eklenirse host key saklama, kullanıcı authentication/authorization, kanal türleri ve remote command çalıştırma sınırları ayrı tasarımdan geçer; libssh2 client API'sine server özelliği atfedilmez.

Kabul testleri: bilinmeyen/değişmiş host key, doğru/yanlış credentials, çok turlu challenge, encrypted key, algoritma uyuşmazlığı, short I/O, rekey sırasında aktarım, stdout/stderr baskısı, exit status/signal, bağlantı kopması, iptal ve timeout. SFTP için boş/büyük dosya, Unicode/ad çakışması, path traversal, disk dolması, remote permission, rename capability ve kısmi batch sonucu test edilir. DLL/LIB Runner ve CLI aynı test sunucusunda aynı sonuç sözleşmesini doğrular; harici komut ve transfer testleri yalnız izole fixture hedeflerinde yürütülür.

## 28. Teknik kaynaklar

Bu belge bir tasarım önerisidir; kaynaklar platform/API özelliklerini destekler, SDK'nın uygulanmış veya test edilmiş olduğunu göstermez. İnceleme tarihi 10 Eylül 2026'dır.

- [Microsoft CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal): Windows kriptografi katmanlarının seçimi.
- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt): şifreleme çağrısı ve parametre sınırları.
- [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom): sistem RNG kullanımı.
- [BCryptDeriveKeyPBKDF2](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekeypbkdf2): ilk parola KDF adaptörü.
- [Embarcadero derleyici aileleri](https://docwiki.embarcadero.com/RADStudio/Athens/en/C%2B%2B_Compilers): ABI ve derleyici ayrımı.
- [Embarcadero modern özellikleri](https://docwiki.embarcadero.com/RADStudio/Athens/en/Modern_C%2B%2B_Features_Supported_by_RAD_Studio_Clang-enhanced_C%2B%2B_Compilers): ortak/modern wrapper ayrımı.
- [Botan build](https://botan.randombit.net/handbook/building.html): sağlayıcı derleme gereksinimleri.
- [Crypto++ compilers](https://www.cryptopp.com/wiki/Compilers): derleyici desteği değerlendirmesi.
- [OpenSSL libcrypto](https://docs.openssl.org/3.0/man7/crypto/): EVP/provider temelli adaptör.
- [RFC 9580 OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html): OpenPGP biçim ve mesaj katmanı.
- [RNP](https://github.com/rnpgp/rnp): OpenPGP motor adayı.
- [GPGME](https://gnupg.org/documentation/manuals/gpgme/Features.html): GnuPG engine adaptörü ve dağıtım değerlendirmesi.
- [Lua manual](https://www.lua.org/manual/5.4/manual.html): gömülü scripting ve C API.
