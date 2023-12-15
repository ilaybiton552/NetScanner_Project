from scapy.all import *
from threading import Thread
import subprocess
import re
import pywifi
import time
import requests
import os
import psutil

DNS_API = "https://networkcalc.com/api/dns/lookup/"
SYN = 0x02
NUM_SYN_FLOOD_ATTACK_PACKETS = 15
TIME_BETWEEN_SYN_PACKETS = 10


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
    :param packet: DNS packet
    :return: bool, True - an attack, False - not
    """
    domain = packet[DNS].qd.qname.decode('utf-8')
    dns_response = requests.get(DNS_API + domain)
    dns_ip = dns_response.json().get("records").get('A')[0].get('address')
    if dns_ip:
        http_ip = packet[IP].src  # Assuming you are looking for the source IP of the HTTP GET request
        return dns_ip != http_ip
    return False


def is_syn_flood_attack(packet):
    """
    Checks if a SYN Flood attack occurred
    :param packet: TCP SYN packet
    :return: bool, True - at attack, False - not
    """
    if IP in packet:
        sender_ip = packet[IP].src
        # computer sent more than 15 tcp syn packets in the last 10 seconds - syn flood attack
        return sniffer.add_ip(sender_ip) >= NUM_SYN_FLOOD_ATTACK_PACKETS


def handle_packet(packet):
    """
    Handles the packet after it got filter (check for an attack)
    :param packet: the filtered packet
    :return: None
    """
    # if DNS packet - check for DNS poisoning
    if DNS in packet:
        if is_dns_poisoning(packet):
            print("DNS Attack detected")


    # if TCP packet - check for SYN flag
    elif TCP in packet:
        if is_syn_flood_attack(packet):
            print("SYN Flood attack detected! Attacker - " + sender_ip)


    print(packet.summary())


def filter_packet(packet):
    """
    Filter for the packets relevant only for the attacks
    :param packet: the packet to filter
    :return: True - kind of packet to look for an attack, False - doesn't include protocols for attacks
    """
    return DNS in packet or (TCP in packet and packet[TCP].flags & SYN)


class Sniffer(Thread):
    def __init__(self):
        self.running = True
        self.syn_packets = {}  # dict which contains all of the source IP of senders of TCP SYN packets
        self.start_time = time.perf_counter()  # timer for SYN Flood attack
        super().__init__()

    def run(self):
        sniff(prn=handle_packet, stop_filter=self.stop_filter, lfilter=filter_packet)

    def stop_filter(self, packet):
        return not self.running

    def add_ip(self, ip):
        """
        Adds the ip of the computer which sent tcp syn packet to the dict
        :param ip: string, the ip of the computer
        :return: int, the number of times the computer sent tcp syn packet in the last 10 seconds
        """
        num_of_times = self.syn_packets.get(ip)
        # if doesn't exist (never sent TCP SYN packet before)
        if num_of_times is None:
            self.syn_packets[ip] = [1, time.perf_counter()]
            return 1

        num_of_times = num_of_times[0]
        # if more than 10 seconds without SYN attack passed - reset count or already counted as SYN Flood attack
        if time.perf_counter() - self.syn_packets[ip][1] > TIME_BETWEEN_SYN_PACKETS or \
                num_of_times >= NUM_SYN_FLOOD_ATTACK_PACKETS:
            num_of_times = 0
            self.syn_packets[ip] = [1, time.perf_counter()]
        else:
            self.syn_packets[ip][0] = num_of_times + 1
        return num_of_times + 1


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
            else:
                print(f"Failed to connect to {self.ssid}")
        else:
            print(f"Network {self.ssid} not found in scan results")


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

            return networks
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"
        except ValueError as e:
            return f"Error: {e}"


def start_sniffing():
    """
    the function activates the sniffing
    :return: None
    """
    global sniffer
    sniffer = Sniffer()
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
