from scapy.all import *
from threading import Thread
import subprocess
import re
import pywifi
import time
import requests


DNS_API = "https://networkcalc.com/api/dns/lookup/"


def handle_packet(packet):
    # if DNS packet - check for DNS poisoning
    if DNS in packet:
        domain = packet[DNS].qd.qname.decode('utf-8')
        response = requests.get(DNS_API + domain)
    print(packet.summary())


def filter_packet(packet):
    return DNS in packet


class Sniffer(Thread):
    def __init__(self):
        self.running = True
        super().__init__()

    def run(self):
        sniff(prn=handle_packet, stop_filter=self.stop_filter, lfilter=filter_packet)

    def stop_filter(self, packet):
        return self.running


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
