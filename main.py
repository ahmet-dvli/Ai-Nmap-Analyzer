import subprocess
import re
import json 

target = "scanme.nmap.org"

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