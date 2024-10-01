# Nuclei Kullanımı ve Template Oluşturma: Kapsamlı Rehber

## Giriş

Nuclei, güvenlik uzmanları ve penetrasyon testçileri için güçlü ve esnek bir güvenlik tarama aracıdır. Bu yazıda, Nuclei'nin temel kullanımını ve özel template'ler oluşturma sürecini detaylı bir şekilde inceleyeceğiz.

## Nuclei Nedir?

Nuclei, Project Discovery tarafından geliştirilen açık kaynaklı bir güvenlik tarama aracıdır. YAML tabanlı template'ler kullanarak hızlı, özelleştirilebilir ve güvenilir taramalar yapmanıza olanak tanır.

## Nuclei Kurulumu

Nuclei'yi kurmak için aşağıdaki adımları izleyebilirsiniz:

1. Go programlama dilini yükleyin.
2. Terminal veya komut istemcisinde şu komutu çalıştırın:

```
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

## Temel Nuclei Kullanımı

Nuclei'yi kullanmaya başlamak için şu temel komutları bilmeniz yeterlidir:

1. Tek bir hedefe karşı tarama:
```
nuclei -u https://example.com -t nuclei-templates/
```

2. Birden fazla hedefi içeren bir dosyaya karşı tarama:
```
nuclei -l targets.txt -t nuclei-templates/
```

3. Belirli bir template ile tarama:
```
nuclei -u https://example.com -t path/to/template.yaml
```

## Nuclei Template Yapısı

Nuclei template'leri YAML formatında yazılır. İşte temel bir template yapısı:

```yaml
id: example-template
info:
  name: Example Vulnerability Check
  author: Your Name
  severity: medium
  description: This template checks for an example vulnerability.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-path"
    matchers:
      - type: word
        words:
          - "vulnerable string"
```

## Özel Nuclei Template Oluşturma

Şimdi, adım adım özel bir Nuclei template'i nasıl oluşturacağımızı görelim:

1. Template Kimliği ve Bilgileri:
   Öncelikle template'imize bir kimlik ve temel bilgiler ekleyelim.

```yaml
id: custom-xss-check
info:
  name: Custom XSS Vulnerability Check
  author: Your Name
  severity: high
  description: This template checks for a specific XSS vulnerability.
```

2. İstek Detayları:
   Şimdi, yapılacak HTTP isteğinin detaylarını belirleyelim.

```yaml
requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=test"
```

3. Matcher'lar:
   İsteğin sonucunu değerlendirmek için matcher'lar ekleyelim.

```yaml
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<script>alert('XSS')</script>"
        part: body
      - type: status
        status:
          - 200
```

4. Extractors (İsteğe Bağlı):
   Yanıttan belirli bilgileri çıkarmak istiyorsanız, extractor'lar ekleyebilirsiniz.

```yaml
    extractors:
      - type: regex
        part: body
        regex:
          - "user[a-z0-9]+@example\.com"
```

İşte tamamlanmış template örneği:

```yaml
id: custom-xss-check
info:
  name: Custom XSS Vulnerability Check
  author: Your Name
  severity: high
  description: This template checks for a specific XSS vulnerability.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=test"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<script>alert('XSS')</script>"
        part: body
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        part: body
        regex:
          - "user[a-z0-9]+@example\.com"
```

## Template Test Etme ve Doğrulama

Template'inizi oluşturduktan sonra, doğru çalıştığından emin olmak için test etmelisiniz:

1. Template'i kaydedin (örneğin, `custom-xss-check.yaml` olarak).
2. Nuclei ile test edin:
```
nuclei -t custom-xss-check.yaml -u https://test-website.com
```

3. Sonuçları inceleyerek template'in beklendiği gibi çalışıp çalışmadığını kontrol edin.

## İleri Düzey Nuclei Özellikleri

1. Dinamik Değişkenler:
   Nuclei, tarama sırasında dinamik olarak değişebilen değişkenler kullanmanıza olanak tanır.

```yaml
variables:
  username: FUZZ
requests:
  - method: POST
    path:
      - "{{BaseURL}}/login"
    body: "username={{username}}&password=test"
```

2. Çoklu İstekler:
   Bir template içinde birden fazla istek tanımlayabilirsiniz.

```yaml
requests:
  - name: step-1
    # ...
  - name: step-2
    # ...
```

3. Koşullu İstekler:
   Belirli koşullara bağlı olarak istekler yapabilirsiniz.

```yaml
requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
    matchers:
      - type: status
        status:
          - 200
    extractors:
      - type: regex
        name: csrf-token
        regex:
          - 'csrf_token" value="([a-zA-Z0-9]+)"'

  - method: POST
    path:
      - "{{BaseURL}}/admin/settings"
    body: "csrf_token={{csrf-token}}&setting=value"
    matchers:
      - type: word
        words:
          - "Settings updated successfully"
```

## Sonuç

Nuclei, güvenlik taramaları için güçlü ve esnek bir araçtır. Özel template'ler oluşturarak, kendi güvenlik kontrollerinizi otomatize edebilir ve tarama süreçlerinizi özelleştirebilirsiniz. Bu rehberde öğrendiklerinizle artık kendi Nuclei template'lerinizi oluşturmaya ve güvenlik testlerinizi geliştirmeye başlayabilirsiniz.

Unutmayın, güvenlik taramaları yaparken etik kurallara uymak ve yalnızca izin verilen sistemler üzerinde çalışmak önemlidir. İyi taramalar!  
