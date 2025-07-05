# 🔍 Discord YARA Tarama Botu

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![Discord.py](https://img.shields.io/badge/discord.py-v2.5+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Discord YARA Tarama Botu**, Discord üzerinden dosyaları YARA kuralları ile tarayan ve detaylı güvenlik analizi sunan profesyonel bir bottur. Siber güvenlik uzmanları, sistem yöneticileri ve güvenlik araştırmacıları için tasarlanmıştır.

## ✨ Özellikler

- 🔍 **YARA Kuralları ile Tarama** - Kapsamlı malware tespiti
- 📊 **Detaylı Dosya Analizi** - Hash değerleri, entropi, dosya tipi
- 🛡️ **PE Dosya Analizi** - Windows çalıştırılabilir dosyalar için özel analiz
- 📜 **String Çıkarma** - Dosyalardaki okunabilir metinleri çıkarma
- 🔗 **URL Tespiti** - Dosya içindeki URL'leri bulma
- 📤 **VirusTotal Entegrasyonu** - Kolay yükleme butonu
- 🔐 **Güvenli Loglama** - Şifreli ZIP ile dosya saklama
- ⚡ **Hızlı Tarama** - Optimize edilmiş performans

## 🚀 Kurulum

### Gereksinimler

- Python 3.7 veya daha yeni
- Discord hesabı ve bot token'ı
- Windows/Linux/macOS

### 1. Projeyi İndirin

```bash
git clone https://github.com/yourusername/discord-yara-scanner.git
cd discord-yara-scanner
```

### 2. Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### 3. Discord Bot Oluşturun

1. [Discord Developer Portal](https://discord.com/developers/applications) adresine gidin
2. "New Application" → Bot ismi girin
3. "Bot" sekmesine gidin → "Add Bot"
4. Token'ı kopyalayın

### 4. Yapılandırma

`.env` dosyasını oluşturun:

```env
DISCORD_TOKEN=your_bot_token_here
LOG_CHANNEL_ID=123456789012345678  # İsteğe bağlı
ALLOWED_CHANNEL_ID=123456789012345678  # İsteğe bağlı
```

### 5. Botu Başlatın

**Manuel:**
```bash
python bot.py
```

**Windows BAT Dosyası ile:**
```bash
start_bot.bat
```

## 📋 Komutlar

| Komut | Açıklama |
|-------|----------|
| `/tara [dosya]` | Dosyayı YARA kuralları ile tarar ve detaylı analiz sunar |
| `/yaralist` | Yüklü YARA kurallarını listeler |
| `/tara-help` | Yardım menüsünü gösterir |
| `/bütünlük-kontrolü` | Bot dosyalarının bütünlüğünü kontrol eder |

## 🎯 Kullanım

### Dosya Tarama

1. Discord'da `/tara` komutunu yazın
2. Taranacak dosyayı ekleyin
3. Enter'a basın
4. Bot detaylı analiz sonucunu gösterecek

### Sonuç Örneği

```
🔍 Tarama Sonucu: example.exe

ℹ️ Genel Dosya Bilgileri
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb924...
Boyut: 1024.00 KB
Dosya Tipi: PE32 executable
Entropi: 6.8542 (Yüksek > 7.0)

✅ YARA Sonucu
Temiz. Herhangi bir YARA eşleşmesi bulunamadı.
```

## 🛡️ YARA Kuralları

Bot, `yara_rules/` klasöründeki `.yar` ve `.yara` dosyalarını kullanır. Mevcut kurallar:

- **Malware Tespiti** - Çeşitli zararlı yazılım aileleri
- **Packer Tespiti** - UPX, Themida, VMProtect
- **Cheat/Hack Tespiti** - Oyun hileleri ve hack araçları
- **Process Hollowing** - Gelişmiş saldırı teknikleri
- **PowerShell Saldırıları** - Zararlı script tespiti

### Kendi YARA Kurallarınızı Ekleme

1. `.yar` veya `.yara` dosyanızı `yara_rules/` klasörüne koyun
2. Botu yeniden başlatın
3. `/yaralist` komutu ile kontrol edin

## ⚙️ Yapılandırma

### Ortam Değişkenleri

- `DISCORD_TOKEN` - Discord bot token'ı (zorunlu)
- `LOG_CHANNEL_ID` - Taranan dosyaların kaydedileceği kanal ID'si
- `ALLOWED_CHANNEL_ID` - Sadece bu kanalda tarama yapılmasına izin ver

### Güvenlik Özellikleri

- **Şifreli Loglama**: Taranan dosyalar AES-256 ile şifrelenir
- **Kanal Kısıtlaması**: Belirli kanallarda çalışacak şekilde sınırlandırma
- **Dosya Boyut Limiti**: Discord'un dosya boyut limitine uyum

## 🔧 Geliştirme

### Proje Yapısı

```
discord-yara-scanner/
├── bot.py              # Ana bot kodu
├── start_bot.bat       # Windows başlatıcı
├── requirements.txt    # Python bağımlılıkları
├── .env               # Yapılandırma dosyası
├── yara_rules/        # YARA kuralları klasörü
│   └── ornek_kural.yar
├── build_info.txt     # Derleme bilgileri
├── hashes.json        # Dosya bütünlük kontrolleri
└── README.md          # Bu dosya
```

### Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Commit yapın (`git commit -m 'Add amazing feature'`)
4. Push yapın (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📊 İstatistikler

- **Desteklenen Dosya Formatları**: PE, ELF, Mach-O, ve daha fazlası
- **YARA Kuralları**: 50+ önceden tanımlanmış kural
- **Tarama Hızı**: ~2-5 saniye (dosya boyutuna bağlı)
- **Maksimum Dosya Boyutu**: 25MB (Discord limiti)

## 🐛 Sorun Giderme

### Yaygın Hatalar

**"YARA kuralları yüklenemedi"**
- `yara_rules/` klasörünün var olduğunu kontrol edin
- YARA kurallarının doğru formatta olduğunu kontrol edin

**"Token bulunamadı"**
- `.env` dosyasındaki token'ın doğru olduğunu kontrol edin
- Token'da boşluk olmadığından emin olun

**"Modül bulunamadı"**
- `pip install -r requirements.txt` komutunu çalıştırın

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🤝 Destek

Herhangi bir sorun yaşarsanız:

1. [Issues](https://github.com/yourusername/discord-yara-scanner/issues) sayfasından yeni bir issue açın
2. Detaylı hata mesajını ve adımları paylaşın
3. Sistem bilgilerinizi (OS, Python versiyonu) belirtin

## 📞 İletişim

**Contact DC: @akachu @alsiaw**

---

⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!
