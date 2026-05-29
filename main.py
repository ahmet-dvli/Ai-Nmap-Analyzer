import os
from dotenv import load_dotenv
from openai import OpenAI
import subprocess
import re
import sys
import json

target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

command = ["nmap","-sV", target]

result = subprocess.run(command, capture_output=True , text=True)

scan_output = result.stdout

with open("scan.txt","w") as file:
    file.write(scan_output)

print(scan_output)

with open("scan.txt", "r") as file:
    data = file.read()

print("ANALİZ BAŞLIYOR...")

results = []

for line in data.splitlines():
    match = re.match(r"(\d+/tcp)\s+(\w+)\s+(\w+)\s+(.*)", line)

    if match:
        results.append({
            "port": match.group(1),
            "state": match.group(2),
            "service": match.group(3),
            "version": match.group(4)
        })

print(results)

print("RİSK ANALİZCİSİ:")

for item in results:
    port = item["port"]
    service = item["service"]
    version = item["version"]

    if port == "22/tcp":
        print(f"[Yüksek Risk] {port} SSH açık -> Brute Force Riski")

    elif port == "80/tcp":
        print(f"[Orta Risk] {port} HTTP açık -> Web Attack Surface Riski")

    elif "filtered" in item.get("state", ""):
        print(f"[BİLGİ] {port} {service} -> filtered (Firewall olabilir.)")
    
    else:
        print(f"[Düşük/Belirsiz] {port} {service} -> Daha gelişmiş bir analizci lazım.")

    
with open("results.json", "w") as f:
    json.dump(results, f, indent=4)

print("JSON export tamamlandı → results.json oluşturuldu")

from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


prompt = f"""
Sen bir siber güvenlik analistisin.

Aşağıdaki Nmap tarama sonuçlarını analiz et ve Türkçe rapor yaz:

- Her port için risk seviyesi (Yüksek / Orta / Düşük)
- Neden riskli olduğunu açıkla
- Kısa öneriler ver

Veri:
{json.dumps(results, indent=2)}
"""

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "Sen deneyimli bir siber güvenlik uzmanısın."},
        {"role": "user", "content": prompt}
    ]
)

print("YAPAY ZEKA GÜVENLİK RAPORU")
print(response.choices[0].message.content)