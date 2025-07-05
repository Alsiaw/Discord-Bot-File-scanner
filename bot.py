import discord
from discord import File
from discord.ui import View, Button
import os
import yara
import pefile
from dotenv import load_dotenv
import re
import hashlib
import math
from datetime import datetime
import time
import magic
import io
import pyzipper
import json

load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID")
ALLOWED_CHANNEL_ID = os.getenv("ALLOWED_CHANNEL_ID")

YARA_RULES_PATH = 'yara_rules'

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)
tree = discord.app_commands.CommandTree(client)

def load_yara_rules():
    filepaths = {}
    for root, _, files in os.walk(YARA_RULES_PATH):
        for filename in files:
            if filename.endswith(('.yar', '.yara')):
                filepath = os.path.join(root, filename)
                filepaths[filename] = filepath
    if not filepaths:
        return None, 0
    try:
        return yara.compile(filepaths=filepaths), len(filepaths)
    except yara.Error as e:
        print(f"YARA kural hatası: {e}")
        return None, 0

rules, rule_count = load_yara_rules()

class ScanResultView(View):
    def __init__(self):
        super().__init__(timeout=None)
        upload_url = "https://www.virustotal.com/gui/home/upload"
        self.add_item(Button(label="VirusTotal'da Yükle & Tara", style=discord.ButtonStyle.link, url=upload_url, emoji="📤"))

def calculate_entropy(data):
    if not data:
        return 0
    freq_map = {}
    data_len = len(data)
    for byte in data:
        freq_map[byte] = freq_map.get(byte, 0) + 1
    entropy = 0
    for count in freq_map.values():
        p_x = count / data_len
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def calculate_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error calculating hash for {filepath}: {e}")
        return None

@client.event
async def on_ready():
    if rules is not None:
        print(f'{client.user} olarak giriş yapıldı.')
        print(f'{rule_count} YARA kural dosyası başarıyla yüklendi.')
        await tree.sync()
    else:
        print("YARA kuralları yüklenemedi, bot başlatılamıyor.")
        await client.close()

@tree.command(name="tara-help", description="Bot komutları hakkında yardım bilgisi verir.")
async def help_command(interaction):
    embed = discord.Embed(
        title="Yardım Menüsü",
        description="YARA Tarama Botu Komutları",
        color=discord.Color.blue()
    )
    embed.add_field(name="/tara [dosya]", value="Eklenen dosyayı YARA kuralları ile tarar ve detaylı analiz sunar.", inline=False)
    embed.add_field(name="/yaralist", value="Mevcut YARA kurallarını listeler.", inline=False)
    embed.add_field(name="/tara-help", value="Bu yardım menüsünü gösterir.", inline=False)
    embed.add_field(name="/bütünlük-kontrolü", value="Dosyaların bütünlüğünü ve derleme tarihini kontrol eder.", inline=False)
    await interaction.response.send_message(embed=embed)

@tree.command(name="yaralist", description="Mevcut YARA kurallarını listeler.")
async def yara_list(interaction):
    if not os.path.exists(YARA_RULES_PATH) or not os.listdir(YARA_RULES_PATH):
        await interaction.response.send_message("Hiç YARA kuralı bulunamadı.")
        return
    rule_files = [f for f in os.listdir(YARA_RULES_PATH) if f.endswith(('.yar', '.yara'))]
    embed = discord.Embed(
        title="Yüklü YARA Kuralları",
        description="\n".join(rule_files),
        color=discord.Color.green()
    )
    await interaction.response.send_message(embed=embed)

@tree.command(name="bütünlük-kontrolü", description="Dosyaların bütünlüğünü ve derleme tarihini kontrol eder.")
async def integrity_check(interaction: discord.Interaction):
    await interaction.response.defer()
    build_info_path = 'build_info.txt'
    hashes_path = 'hashes.json'
    embed = discord.Embed(
        title="Bütünlük Kontrolü Sonucu",
        color=discord.Color.gold()
    )
    try:
        with open(build_info_path, 'r', encoding='utf-8') as f:
            build_info = f.read()
        embed.add_field(name="ℹ️ Derleme Bilgisi", value=f"```\n{build_info}\n```", inline=False)
    except FileNotFoundError:
        embed.add_field(name="⚠️ Derleme Bilgisi Bulunamadı", value=f"`{build_info_path}` dosyası mevcut değil.", inline=False)
        await interaction.followup.send(embed=embed)
        return
    try:
        with open(hashes_path, 'r', encoding='utf-8') as f:
            hashes_data = json.load(f)
    except FileNotFoundError:
        embed.add_field(name="⚠️ Hash Dosyası Bulunamadı", value=f"`{hashes_path}` dosyası mevcut değil.", inline=False)
        await interaction.followup.send(embed=embed)
        return
    except json.JSONDecodeError:
        embed.add_field(name="❌ Hash Dosyası Hatası", value=f"`{hashes_path}` dosyası geçerli bir JSON formatında değil.", inline=False)
        await interaction.followup.send(embed=embed)
        return
    results = []
    all_match = True
    for item in hashes_data.get("files_to_check", []):
        name = item.get("name", "İsimsiz Dosya")
        path = item.get("path")
        expected_hash = item.get("expected_sha256")
        if not path or not expected_hash:
            results.append(f"❓ **{name}**: Yapılandırma eksik (path veya hash belirtilmemiş).")
            all_match = False
            continue
        current_hash = calculate_file_sha256(path)
        if current_hash is None:
            result_text = f"❌ **{name}**: Dosya bulunamadı (`{path}`)"
            all_match = False
        elif current_hash.lower() == expected_hash.lower():
            result_text = f"✅ **{name}**: Eşleşti"
        else:
            result_text = f"❌ **{name}**: Eşleşmedi\n   - **Beklenen:** `{expected_hash[:16]}...`\n   - **Mevcut:** `{current_hash[:16]}...`"
            all_match = False
        results.append(result_text)
    if results:
        embed.add_field(
            name="📄 Dosya Bütünlük Durumu",
            value="\n".join(results),
            inline=False
        )
    else:
        embed.add_field(
            name="📄 Dosya Bütünlük Durumu",
            value="Kontrol edilecek dosya bulunamadı.",
            inline=False
        )
    if all_match:
        embed.color = discord.Color.green()
        embed.description = "Tüm dosyalar doğrulandı."
    else:
        embed.color = discord.Color.red()
        embed.description = "Bazı dosyalarda uyuşmazlık veya hata tespit edildi."
    await interaction.followup.send(embed=embed)

@tree.command(name="tara", description="Bir dosyayı YARA kurallarıyla tarar ve detaylı analiz eder.")
@discord.app_commands.describe(dosya='Taranacak dosyayı ekleyin.')
async def tara(interaction: discord.Interaction, dosya: discord.Attachment):
    if ALLOWED_CHANNEL_ID and str(interaction.channel.id) != ALLOWED_CHANNEL_ID:
        await interaction.response.send_message(
            f"Bu komutu sadece <#{ALLOWED_CHANNEL_ID}> kanalında kullanabilirsiniz.", 
            ephemeral=True
        )
        return
    await interaction.response.defer()
    if rules is None:
        await interaction.followup.send("YARA kuralları yüklenemediği için tarama yapılamıyor.")
        return
    strings_filepath = f"strings_{dosya.filename}.txt"
    try:
        start_time = time.time()
        file_content = await dosya.read()
        matches = rules.match(data=file_content)
        with open(strings_filepath, "w", encoding="utf-8") as f:
            printable_strings = re.findall(b"[\x20-\x7E]{5,}", file_content)
            for s in printable_strings:
                f.write(s.decode("utf-8", errors="ignore") + "\n")
        strings_file_for_discord = File(strings_filepath)
        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()
        entropy = calculate_entropy(file_content)
        file_type = magic.from_buffer(file_content)
        embed = discord.Embed(
            title=f"🔍 Tarama Sonucu: {dosya.filename}",
            color=discord.Color.dark_grey()
        )
        embed.add_field(
            name="ℹ️ Genel Dosya Bilgileri",
            value=f"**MD5:** `{md5_hash}`\n"
                  f"**SHA1:** `{sha1_hash}`\n"
                  f"**SHA256:** `{sha256_hash}`\n"
                  f"**Boyut:** `{len(file_content) / 1024:.2f} KB`\n"
                  f"**Dosya Tipi:** `{file_type}`\n"
                  f"**Entropi:** `{entropy:.4f}` (Yüksek > 7.0)",
            inline=False
        )
        if matches:
            embed.color = discord.Color.red()
            packer_detected = False
            yara_results_value = ""
            for match in matches:
                if yara_results_value:
                    yara_results_value += "\n---\n"
                rule_details = f"**Kural:** `{match.rule}`\n"
                if 'description' in match.meta:
                    rule_details += f"**Açıklama:** *{match.meta['description']}*\n"
                if 'author' in match.meta:
                    rule_details += f"**Yazar:** `{match.meta['author']}`\n"
                if match.strings:
                    try:
                        instance = match.strings[0].instances[0]
                        string_preview = instance.matched_data.decode('utf-8', 'ignore').replace('`', '\\`')[:100]
                        rule_details += f"**Eşleşen Dize:** `{string_preview}...`\n"
                    except IndexError:
                        pass
                yara_results_value += rule_details
                if "packer" in match.rule.lower() or "upx" in match.rule.lower() or match.meta.get('type') == 'packer':
                    packer_detected = True
            embed.add_field(name="🚨 YARA TESPİT EDİLDİ!", value=yara_results_value, inline=False)
            if packer_detected:
                embed.add_field(name="⚠️ Packer Tespiti", value="Bu dosyanın içeriğini gizlemek için paketlenmiş (packed) olabileceğine dair bir kural tetiklendi. Analiz daha zor olabilir.", inline=False)
        else:
            embed.color = discord.Color.green()
            embed.add_field(name="✅ YARA Sonucu", value="Temiz. Herhangi bir YARA eşleşmesi bulunamadı.", inline=False)
        embed.add_field(name="📜 Çıkarılan Dizeler (Strings)", value="Dosyadaki tüm okunabilir dizeler ekteki `.txt` dosyasına kaydedildi.", inline=False)
        try:
            pe = pefile.PE(data=file_content)
            compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            signature_info = "İmzasız" 
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                signature_info = "İmzalı (Doğrulama yapılmadı)"
            embed.add_field(
                name="📦 PE Bilgileri",
                value=f"**Derleme Zamanı:** `{compile_time.strftime('%Y-%m-%d %H:%M:%S')}`\n"
                      f"**Giriş Noktası:** `{hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}`\n"
                      f"**🛡️ Dijital İmza:** {signature_info}",
                inline=False
            )
            sections = [s.Name.decode().rstrip('\x00') for s in pe.sections]
            if sections:
                embed.add_field(name="📊 Sections", value=' | '.join(f'`{s}`' for s in sections), inline=False)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                dlls = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
                embed.add_field(name="📚 Imported DLLs", value="`" + "`, `".join(dlls[:15]) + "`", inline=False)
            urls = re.findall(br'https?://[\w\d\-./?=#&]+', file_content)
            if urls:
                decoded_urls = [u.decode('utf-8', 'ignore') for u in urls]
                embed.add_field(name="🔗 Bulunan URL'ler", value="\n".join(f"`{u}`" for u in decoded_urls[:10]), inline=False)
        except pefile.PEFormatError:
            pass
        end_time = time.time()
        scan_duration = end_time - start_time
        yara_rule_files = [f for f in os.listdir(YARA_RULES_PATH) if f.endswith(('.yar', '.yara'))]
        rule_count = len(yara_rule_files)
        embed.set_footer(text=f"Tarama {scan_duration:.2f} saniye sürdü | {rule_count} YARA kuralı kullanıldı.")
        view = ScanResultView()
        await interaction.followup.send(embed=embed, view=view, file=strings_file_for_discord)
        if LOG_CHANNEL_ID:
            try:
                log_channel = await client.fetch_channel(int(LOG_CHANNEL_ID))
                zip_password = b"123"
                in_memory_zip = io.BytesIO()
                with pyzipper.AESZipFile(in_memory_zip, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(zip_password)
                    zf.writestr(dosya.filename, file_content)
                in_memory_zip.seek(0)
                logged_file = discord.File(in_memory_zip, filename=f"{sha256_hash}.zip")
                log_message = (
                    f"Taranan dosya: `{dosya.filename}` (SHA256: `{sha256_hash}`)\n"
                    f"Kullanıcı: {interaction.user.mention}\n\n"
                    f"**UYARI:** Bu dosya potansiyel olarak zararlı olabilir ve Discord'un virüs filtresini atlatmak için şifreli zip olarak gönderildi.\n"
                    f"**ZIP Şifresi:** `{zip_password.decode()}`"
                )
                await log_channel.send(content=log_message, file=logged_file)
            except (ValueError, TypeError):
                print(f"HATA: .env dosyasındaki LOG_CHANNEL_ID geçerli bir sayı değil.")
            except discord.NotFound:
                print(f"HATA: {LOG_CHANNEL_ID} ID'li kanal bulunamadı.")
            except discord.Forbidden:
                print(f"HATA: {LOG_CHANNEL_ID} ID'li kanala mesaj gönderme izni yok.")
            except Exception as e:
                print(f"Log kanalına gönderimde beklenmedik bir hata oluştu: {e}")
    except Exception as e:
        await interaction.followup.send(f"Bir hata oluştu: {e}")
    finally:
        if os.path.exists(strings_filepath):
            os.remove(strings_filepath)

if __name__ == "__main__":
    if TOKEN:
        client.run(TOKEN)
    else:
        print("HATA: DISCORD_TOKEN bulunamadı. Lütfen .env dosyasını kontrol edin.")
