# 🔍 Discord YARA Scanner Bot

![Python](https://img.shields.io/badge/python-v3.7+-blue.svg)
![Discord.py](https://img.shields.io/badge/discord.py-v2.5+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Discord YARA Scanner Bot** is a professional bot that scans files through Discord using YARA rules and provides detailed security analysis. Designed for cybersecurity experts, system administrators, and security researchers.

## ✨ Features

- 🔍 **YARA Rule Scanning** - Comprehensive malware detection
- 📊 **Detailed File Analysis** - Hash values, entropy, file type analysis
- 🛡️ **PE File Analysis** - Specialized analysis for Windows executables
- 📜 **String Extraction** - Extract readable text from files
- 🔗 **URL Detection** - Find URLs within files
- 📤 **VirusTotal Integration** - Easy upload button
- 🔐 **Secure Logging** - File storage with encrypted ZIP
- ⚡ **Fast Scanning** - Optimized performance

## 🚀 Installation

### Requirements

- Python 3.7 or newer
- Discord account and bot token
- Windows/Linux/macOS

### 1. Download the Project

```bash
git clone https://github.com/yourusername/discord-yara-scanner.git
cd discord-yara-scanner
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Create Discord Bot

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. "New Application" → Enter bot name
3. Go to "Bot" tab → "Add Bot"
4. Copy the token

### 4. Configuration

Create `.env` file:

```env
DISCORD_TOKEN=your_bot_token_here
LOG_CHANNEL_ID=123456789012345678  # Optional
ALLOWED_CHANNEL_ID=123456789012345678  # Optional
```

### 5. Start the Bot

**Manual:**
```bash
python bot.py
```

**Windows BAT File:**
```bash
start_bot.bat
```

## 📋 Commands

| Command | Description |
|---------|-------------|
| `/tara [file]` | Scans file with YARA rules and provides detailed analysis |
| `/yaralist` | Lists loaded YARA rules |
| `/tara-help` | Shows help menu |
| `/bütünlük-kontrolü` | Checks bot file integrity |

## 🎯 Usage

### File Scanning

1. Type `/tara` command in Discord
2. Attach the file to scan
3. Press Enter
4. Bot will show detailed analysis results

### Example Result

```
🔍 Scan Result: example.exe

ℹ️ General File Information
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256: e3b0c44298fc1c149afbf4c8996fb924...
Size: 1024.00 KB
File Type: PE32 executable
Entropy: 6.8542 (High > 7.0)

✅ YARA Result
Clean. No YARA matches found.
```

## 🛡️ YARA Rules

The bot uses `.yar` and `.yara` files from the `yara_rules/` folder. Current rules include:

- **Malware Detection** - Various malware families
- **Packer Detection** - UPX, Themida, VMProtect
- **Cheat/Hack Detection** - Game cheats and hack tools
- **Process Hollowing** - Advanced attack techniques
- **PowerShell Attacks** - Malicious script detection

### Adding Your Own YARA Rules

1. Place your `.yar` or `.yara` file in the `yara_rules/` folder
2. Restart the bot
3. Check with `/yaralist` command

## ⚙️ Configuration

### Environment Variables

- `DISCORD_TOKEN` - Discord bot token (required)
- `LOG_CHANNEL_ID` - Channel ID for logging scanned files
- `ALLOWED_CHANNEL_ID` - Restrict scanning to specific channel only

### Security Features

- **Encrypted Logging**: Scanned files are encrypted with AES-256
- **Channel Restriction**: Limit bot to work in specific channels
- **File Size Limit**: Complies with Discord's file size limits

## 🔧 Development

### Project Structure

```
discord-yara-scanner/
├── bot.py              # Main bot code
├── start_bot.bat       # Windows launcher
├── requirements.txt    # Python dependencies
├── .env               # Configuration file
├── yara_rules/        # YARA rules folder
│   └── ornek_kural.yar
├── build_info.txt     # Build information
├── hashes.json        # File integrity checks
└── README.md          # This file
```

### Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📊 Statistics

- **Supported File Formats**: PE, ELF, Mach-O, and more
- **YARA Rules**: 50+ predefined rules
- **Scan Speed**: ~2-5 seconds (depending on file size)
- **Maximum File Size**: 25MB (Discord limit)

## 🐛 Troubleshooting

### Common Errors

**"YARA rules could not be loaded"**
- Check that `yara_rules/` folder exists
- Verify YARA rules are in correct format

**"Token not found"**
- Check that token in `.env` file is correct
- Make sure there are no spaces in the token

**"Module not found"**
- Run `pip install -r requirements.txt`

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

## 🤝 Support

If you encounter any issues:

1. Open a new issue on [Issues](https://github.com/yourusername/discord-yara-scanner/issues) page
2. Share detailed error message and steps
3. Include your system information (OS, Python version)

## 👥 Developed By

**Developed by  💙 alsiaw**

---

⭐ Don't forget to star this project if you like it!
