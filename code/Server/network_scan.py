import ipaddress
from scapy.all import ARP, Ether, srp
import netifaces
import subprocess
import urllib.request
import csv

def download_oui_database(url, filename):
    urllib.request.urlretrieve(url, filename)


def load_oui_database(filename):
    oui_dict = {}
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip the header
        for row in reader:
            oui = row[1].replace('-', ':').lower()
            manufacturer = row[2]
            oui_dict[oui] = manufacturer
    return oui_dict


def get_manufacturer(mac, oui_dict):
    # Get the OUI from the MAC address
    oui = mac.lower()[:8].replace(':', '')
    return oui_dict.get(oui, 'Unknown')


class Computer:
    def __init__(self, ip, mac, manufacturer):
        self.ip = ip
        self.mac = mac
        self.manufacturer = manufacturer


    def __str__(self):
        return f"IP: {self.ip}, MAC: {self.mac}, Manufacturer: {self.manufacturer}"


def get_network(interface):
    addrs = netifaces.ifaddresses(interface)
    ip_address = addrs[netifaces.AF_INET][0]['addr']
    subnet_mask = addrs[netifaces.AF_INET][0]['netmask']
    network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
    print("The found network ", network)
    return network


def get_wireless_interface():
    iwconfig_output = subprocess.check_output(['iwconfig'], universal_newlines=True)
    interface = next((line.split()[0] for line in iwconfig_output.split('\n') if 'ESSID' in line), None)
    print("The wireless interface ", interface)
    return interface


def scan_subnet(subnet, oui_dict):
    print(f"Scanning {subnet}...")
    arp_request = ARP(pdst=str(subnet))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    computers = []
    for sent, received in answered:
        manufacturer = get_manufacturer(received.hwsrc, oui_dict)
        computer = Computer(received.psrc, received.hwsrc, manufacturer)
        computers.append(computer)
    return computers


def get_network_state():
    print("Starting the code...")
    url = 'http://standards-oui.ieee.org/oui/oui.csv'
    filename = 'oui.csv'
    print("Downloading the oui database...")
    download_oui_database(url, filename)
    oui_dict = load_oui_database(filename)
    interface = get_wireless_interface()
    network = get_network(interface)
    computers = scan_subnet(network, oui_dict)
    return computers
