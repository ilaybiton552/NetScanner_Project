from scapy.all import *
from threading import Thread
import subprocess
import re
import pywifi
import time
import requests
import os
import psutil
import EvilTwin

DNS_API = "https://networkcalc.com/api/dns/lookup/"
SYN = 0x02
NUM_POTENTIAL_SPAM_PACKETS = 20
TIME_BETWEEN_POTENTIAL_SPAM_PACKETS = 5
DNS_VALID_STATUS = "OK"
ARP_ANSWER_PACKET = 2
BROADCAST = "ff:ff:ff:ff:ff:ff"


def get_wireless_interfaces():
    wireless_interfaces = []

    for interface, details in psutil.net_if_addrs().items():
        for detail in details:
            if detail.family == psutil.AF_INET and 'wireless' in detail.address:
                wireless_interfaces.append(interface)

    return wireless_interfaces


def enable_monitor_mode(interface):
    try:
        # Run the command to enable monitor mode
        os.system(f"sudo iw dev {interface} set type monitor")
        print(f"Monitor mode enabled on {interface}")
    except Exception as e:
        print(f"Error: {e}")


def turn_on_monitor_mode():
    # Get the list of wireless interfaces
    wireless_interfaces = get_wireless_interfaces()

    if wireless_interfaces:
        print("Wireless Interfaces:")
        for interface in wireless_interfaces:
            print(interface)

        # Enable monitor mode on the first wireless interface
        enable_monitor_mode(wireless_interfaces[0])
    else:
        print("No wireless interfaces found.")


def is_dns_poisoning(packet):
    """
    Checks if a packet is a DNS Poisoning attack
    :param packet: DNS answer packet
    :return: bool, True - an attack, False - not
    """
    if packet[DNS].qd is None:
        return False
    domain = packet[DNS].qd.qname.decode()[0:-1]
    packet_ip = packet[DNS].an.rdata
    dns_response = requests.get(DNS_API + domain)
    response_json = dns_response.json()
    if response_json.get("status") == DNS_VALID_STATUS:
        response_ip = response_json.get("records").get('A')[0].get('address')
        return response_ip != packet_ip
    return False


def add_ip(ip, sniffer_dict):
    """
    Adds the ip of the computer which sent spam packet to the dict
    :param ip: string, the ip of the computer
    :param sniffer_dict: dict, the relevant dict of the sniffer for the relevant attack
    :return: int, the number of times the computer sent spam packet in the last 5 seconds
    """
    num_of_times = sniffer_dict.get(ip)
    # if doesn't exist (never sent TCP SYN packet before)
    if num_of_times is None:
        sniffer_dict[ip] = [1, time.perf_counter()]
        return 1

    num_of_times = num_of_times[0]
    # if more than 5 seconds without spam attack passed - reset count or already counted as spam attack
    if time.perf_counter() - sniffer_dict[ip][1] > TIME_BETWEEN_POTENTIAL_SPAM_PACKETS or \
        num_of_times >= NUM_POTENTIAL_SPAM_PACKETS:
        num_of_times = 0
        sniffer_dict[ip] = [1, time.perf_counter()]
    else:
        sniffer_dict[ip][0] = num_of_times + 1
    return num_of_times + 1


def is_syn_flood_attack(packet):
    """
    Checks if a SYN Flood attack occurred
    :param packet: TCP SYN packet
    :return: bool, True - an attack, False - not
    """
    if IP in packet:
        sender_ip = packet[IP].src
    else:  # TCP can only be with IP or IPv6
        sender_ip = packet[IPv6].src
    # computer sent more than 20 tcp syn packets in the last 5 seconds - syn flood attack
    return add_ip(sender_ip, sniffer.syn_packets) >= NUM_POTENTIAL_SPAM_PACKETS, sender_ip


def is_smurf_attack(packet):
    """
    Checks if a SMURF attack occurred
    :param packet: ICMP packet
    :return: bool, True - an attack, False - not
    """
    if IP in packet:
        sender_ip = packet[IP].src
    else:
        sender_ip = packet[IPv6].src
    # computer sent more than 20 tcp syn packets in the last 5 seconds - syn flood attack
    return add_ip(sender_ip, sniffer.icmp_packets) >= NUM_POTENTIAL_SPAM_PACKETS, sender_ip


def handle_packet(packet):
    """
    Handles the packet after it got filter (check for an attack)
    :param packet: the filtered packet
    :return: None
    """
    try:
        # if DNS packet - check for DNS poisoning
        if DNS in packet:
            if is_dns_poisoning(packet):
                print("DNS Attack detected")
        # if ARP packet - check for ARP spoofing attack
        elif ARP in packet:
            packet_ip = packet[ARP].psrc
            packet_mac = packet[ARP].hwsrc
            answer = srp1(Ether(dst=BROADCAST) / ARP(pdst=packet_ip), timeout=2, verbose=False)
            if answer is not NoneType:
                if ARP in answer:
                    real_mac = answer[ARP].hwsrc
                    if real_mac is not None and real_mac != packet_mac:
                        print(f"ARP Spoofing attack detected! Real Mac - {real_mac}, Fake Mac - {packet_mac}")
        # if ICMP packet - check for SMURF attack
        elif ICMP in packet:
            check = is_smurf_attack(packet)
            if check[0]:
                print(f"SMURF attack detected! Attacker - {check[1]}")
        # if TCP packet - check for SYN Flood attack
        elif TCP in packet:
            check = is_syn_flood_attack(packet)
            if check[0]:
                print(f"SYN Flood attack detected! Attacker - {check[1]}")
        elif packet.haslayer(Dot11Beacon):
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            detector = EvilTwinDetector(iface)
            detector.handle_beacon(packet)
    except Exception:
        pass
    print(packet.summary())


class Sniffer(Thread):
    def __init__(self, dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin):
        self.running = True
        self.dns_poisoning = dns_poisoning
        self.syn_flood = syn_flood
        self.arp_spoofing = arp_spoofing
        self.smurf = smurf
        self.evil_twin = evil_twin
        self.syn_packets = {}  # dict which contains all of the source IP of senders of TCP SYN packets
        self.icmp_packets = {}  # dict which contains all of the source IP of senders of ICMP packets
        self.start_time = time.perf_counter()  # timer for SYN Flood and SMURF attacks
        super().__init__()

    def run(self):
        sniff(prn=handle_packet, stop_filter=self.stop_filter, lfilter=self.filter_packet)

    def stop_filter(self, packet):
        return not self.running

    def filter_packet(self, packet):
        """
        Filter for the packets relevant only for the attacks
        :param packet: the packet to filter
        :return: True - kind of packet to look for an attack, False - doesn't include protocols for attacks
        """
        return (self.dns_poisoning and DNS in packet and packet[DNS].an is not None) or \
               (self.syn_flood and TCP in packet and packet[TCP].flags & SYN) or \
               (self.arp_spoofing and ARP in packet and packet[ARP].op == ARP_ANSWER_PACKET) or \
               (self.smurf and ICMP in packet and Ether in packet and packet[Ether].dst == BROADCAST)

    def update(self, dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin):
        """
        Updates the sniffer attacks
        :param dns_poisoning: bool, check for dns poisoning attacks
        :param syn_flood: bool, check for syn flood attacks
        :param arp_spoofing: bool, check for arp spoofing attacks
        :param smurf: bool, check for smurf attacks
        :param evil_twin: bool, check for evil twin attacks
        :return: None
        """
        self.dns_poisoning = dns_poisoning
        self.syn_flood = syn_flood
        self.arp_spoofing = arp_spoofing
        self.smurf = smurf
        self.evil_twin = evil_twin


class Network:
    def __init__(self, ssid, network_type, authentication, encryption):
        self.ssid = ssid
        self.network_type = network_type
        self.authentication = authentication
        self.encryption = encryption

    def connect_to_network(self, password):
        """
        Connects to a WiFi network using pywifi.
        :param self: the network itself.
        :type: Network
        :param password: Password for the WiFi network.
        :type: string
        :return:
        """
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]  # Assuming you have only one WiFi interface

        iface.scan()
        time.sleep(2)
        scan_results = iface.scan_results()

        target_network = None
        for result in scan_results:
            if result.ssid == self.ssid:
                target_network = result
                break

        if target_network:
            profile = pywifi.Profile()
            profile.ssid = target_network.ssid
            profile.auth = pywifi.const.AUTH_ALG_OPEN
            profile.akm.append(pywifi.const.AKM_TYPE_WPA2PSK)
            profile.cipher = pywifi.const.CIPHER_TYPE_CCMP
            profile.key = password

            iface.remove_all_network_profiles()
            temp_profile = iface.add_network_profile(profile)

            iface.connect(temp_profile)

            time.sleep(5)  # You may need to adjust the sleep duration based on your system and network

            if iface.status() == pywifi.const.IFACE_CONNECTED:
                print(f"Successfully connected to {self.ssid}")
                return True
            else:
                print(f"Failed to connect to {self.ssid}")
                return False
        else:
            print(f"Network {self.ssid} not found in scan results")
            return False


    def __str__(self):
        return f"SSID: {self.ssid} Network type: {self.network_type} Authentication: {self.authentication} Encryption: {self.encryption}"

    def to_dict(self):
        return {'ssid': self.ssid, 'network_type': self.network_type, 'authentication': self.authentication, 'encryption': self.encryption}

    @staticmethod
    def scan_wifi_networks():
        """
        Scans for available WiFi networks using the netsh command on Windows.
        :return: Returns a list of Networks
        :rtype: list of Networks
        """
        try:
            result = subprocess.run(["netsh", "wlan", "show", "network"], capture_output=True, text=True, check=True)
            network_info = result.stdout
            network_info = network_info.split('\n')

            # Check if there are enough lines in network_info
            if len(network_info) < 5:
                raise ValueError("Not enough lines in network_info")
            # Remove the first 3 lines
            network_info = network_info[4:]

            # Join the modified lines back into a string
            network_info = '\n'.join(network_info)

            # Parse the information and create instances of the Network class
            networks = []
            current_network_info = None
            ssid = network_type = authentication = encryption = None
            counter = 0

            for line in network_info.split('\n'):
                try:
                    line = line.strip()

                    if line.startswith("SSID "):
                        current_network_info = {'ssid': line.split(' : ')[1].strip()}
                        ssid = current_network_info.get('ssid')
                        counter = 1
                    elif line.startswith("Network type"):
                        current_network_info['network_type'] = line.split(':')[-1].strip()
                        network_type = current_network_info.get('network_type')
                        counter += 1
                    elif line.startswith("Authentication"):
                        current_network_info['authentication'] = line.split(':')[-1].strip()
                        authentication = current_network_info.get("authentication")
                        counter += 1
                    elif line.startswith("Encryption"):
                        current_network_info['encryption'] = line.split(':')[-1].strip()
                        encryption = current_network_info.get('encryption')
                        counter += 1
                    elif (counter % 4 == 0):
                        counter = -1
                        networks.append(Network(ssid, network_type, authentication, encryption))
                except Exception:  # error in network details (for example, missing SSID)
                    pass

            return networks
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"
        except ValueError as e:
            return f"Error: {e}"


def start_sniffing(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin):
    """
    the function activates the sniffing
    :return: None
    """
    global sniffer
    sniffer = Sniffer(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin)
    print("[*] Start sniffing...")
    sniffer.start()


def stop_sniffing():
    """
    The method stops the sniffing
    :return:
    """
    sniffer.running = False
    print("[*] Stop sniffing")
    sniffer.join()


def update_sniffer(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin):
    """
    Updates the sniffer attacks
    :param dns_poisoning: bool, check for dns poisoning attacks
    :param syn_flood: bool, check for syn flood attacks
    :param arp_spoofing: bool, check for arp spoofing attacks
    :param smurf: bool, check for smurf attacks
    :param evil_twin: bool, check for evil twin attacks
    :return: None
    """
    sniffer.update(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin)
    print("[*] Update sniffing")


def show_available_networks():
    """
    Displays the list of available WiFi networks.
    :return: None
    """
    networks = Network.scan_wifi_networks()

    if isinstance(networks, list):
        print("Available Networks:")
        for network in networks:
            print(network.ssid)
    else:
        print(networks)
