import os
import sys
import json
import re
import subprocess

from dotenv import load_dotenv
from openai import OpenAI



load_dotenv(dotenv_path=".env")

api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("OPENAI_API_KEY bulunamadı. .env kontrol et!")

client = OpenAI(api_key=api_key)


target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"



command = ["nmap", "-sV", target]
result = subprocess.run(command, capture_output=True, text=True)

scan_output = result.stdout

print(scan_output)



results = []

for line in scan_output.splitlines():
    match = re.match(r"(\d+/tcp)\s+(\w+)\s+(\w+)\s+(.*)", line)

    if match:
        results.append({
            "port": match.group(1),
            "state": match.group(2),
            "service": match.group(3),
            "version": match.group(4)
        })


print("\nANALİZ BAŞLIYOR...\n")
print(results)



print("RİSK ANALİZCİSİ:\n")

for item in results:
    port = item["port"]
    service = item["service"]

    if port == "22/tcp":
        print(f"[Yüksek Risk] {port} SSH -> Brute Force Riski")

    elif port == "80/tcp":
        print(f"[Orta Risk] {port} HTTP -> Web Attack Surface Riski")

    elif item["state"] == "filtered":
        print(f"[BİLGİ] {port} {service} -> Firewall olabilir")

    else:
        print(f"[Düşük/Belirsiz] {port} {service}")



with open("results.json", "w") as f:
    json.dump(results, f, indent=4)

print("\nJSON export tamamlandı → results.json")



prompt = f"""
Sen bir siber güvenlik analistisin.

Aşağıdaki Nmap sonuçlarını analiz et:

- Risk seviyeleri
- Neden riskli
- Öneriler

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


print("nYAPAY ZEKA GÜVENLİK RAPORU\n")
print(response.choices[0].message.content)

print("✔ Tamamlandı")
