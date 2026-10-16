from scapy.all import sniff, IP
import time

print("[*] Testing packet capture...\n")

packets_captured = []

def test_capture(pkt):
    if IP in pkt:
        info = f"{pkt[IP].src} -> {pkt[IP].dst}"
        packets_captured.append(info)
        print(f"[OK] Captured: {info}")

print("[*] Sniffing for 10 seconds...")
try:
    sniff(prn=test_capture, store=0, timeout=10)
except Exception as e:
    print(f"[!] Error: {e}")

print(f"\n[+] Total packets captured: {len(packets_captured)}")

if len(packets_captured) == 0:
    print("\n[!] NO PACKETS CAPTURED!")
    print("[!] Try running as Administrator")
    print("[!] Or install Npcap from: https://nmap.org/npcap/")
else:
    print("[+] Packet capture is working!")
