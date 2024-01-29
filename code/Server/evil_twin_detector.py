import subprocess
from scapy.all import sniff, Dot11
import netifaces
import re


def get_network_interfaces():
    return netifaces.interfaces()


def get_accessible_networks(interface):
    result = subprocess.run(["sudo", "iwlist", interface, "scan"], capture_output=True, text=True)
    networks = re.findall(r'ESSID:"(.*?)"', result.stdout)
    networks = ["hidden network" if network == '\\x00' * 14 else network for network in networks]
    return networks


def enable_monitor_mode(interface): 
    subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
    subprocess.run(["sudo", "iwconfig", interface, "mode", "monitor"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
    print("Enable monitor mode")


def disable_monitor_mode(interface):
    subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
    subprocess.run(["sudo", "iwconfig", interface, "mode", "managed"], check=True)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
    print("Disable monitor mode")


def handle_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            ssid = packet.info.decode()
            bssid = packet.addr3
            print(f"Network detected: {ssid} ({bssid})")
            if ssid in networks:
                if bssid != networks[ssid]:
                    networks[ssid].append(bssid)
                    print(f"Warning: Multiple access points detected for network '{ssid}'. This could be an evil twin attack.")
            else:
                networks[ssid] = [bssid]
                print(f"Network '{ssid}' added to list of known networks.")


interface = ""
networks = {}
if __name__ == "__main__":
    interfaces = get_network_interfaces()
    print("Available network interfaces:", interfaces)
    interface = input("Enter network interface to use: ")
    networks_list = get_accessible_networks(interface)
    print("Accessible networks:", networks_list)
    enable_monitor_mode(interface)
    try:
        sniff(iface=interface, prn=handle_packet)
    finally:
        if (interface != "mon0"):
            disable_monitor_mode(interface)
        print("Sniffing stopped.")
