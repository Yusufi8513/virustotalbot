import telebot
import requests
import time

# ANAHTARLARIN (Tırnak işaretlerini kaldırma)
TOKEN = "8568365287:AAEw6hxE-IzzUiFCvxgO75F4wYwIG0bCf48"
VT_API_KEY = "c01cc6aabf9a5875b766e981d4849f10bbf9e6836f1c8f271ce2316811c4bde1"

bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "Selam! Bana taratmak istediğin dosyayı gönder, VirusTotal üzerinden kontrol edeyim. 🛡️")

@bot.message_handler(content_types=['document'])
def handle_docs(message):
    try:
        msg = bot.reply_to(message, "📥 Dosya alınıyor...")
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)

        bot.edit_message_text("🔍 VirusTotal'e gönderiliyor...", msg.chat.id, msg.message_id)
        
        # VirusTotal API V3 kullanımı
        url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (message.document.file_name, downloaded_file)}
        headers = {"x-apikey": VT_API_KEY}
        
        response = requests.post(url, files=files, headers=headers)
        
        if response.status_code == 200:
            analysis_id = response.json()['data']['id']
            bot.edit_message_text("⌛ Analiz yapılıyor, lütfen 15-20 saniye bekle...", msg.chat.id, msg.message_id)
            
            # Analiz sonucunu beklemek için kısa bir mola
            time.sleep(20)
            
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_resp = requests.get(report_url, headers=headers)
            stats = report_resp.json()['data']['attributes']['stats']
            
            sonuc = (f"📊 **Tarama Sonucu:**\n\n"
                     f"✅ Temiz: {stats['harmless'] + stats['undetected']}\n"
                     f"❌ Zararlı: {stats['malicious']}\n"
                     f"⚠️ Şüpheli: {stats['suspicious']}")
            
            bot.edit_message_text(sonuc, msg.chat.id, msg.message_id, parse_mode="Markdown")
        else:
            bot.edit_message_text("❌ VirusTotal hatası: " + str(response.status_code), msg.chat.id, msg.message_id)

    except Exception as e:
        bot.reply_to(message, "Hata oluştu: " + str(e))

bot.infinity_polling()
      
