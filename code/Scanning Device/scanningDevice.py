from scapy.all import *
from threading import Thread
import socket
import subprocess
import re
import pywifi
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 666
RECV = 1024

class Sniffer(Thread):
    def __init__(self):
        self.count = 0
        self.running = True
        super().__init__()

    def run(self):
        sniff(prn=self.print_packet, stop_filter=self.stop_filter)

    def print_packet(self, packet):
        print(packet.summary())

    def stop_filter(self, packet):
        if self.count >= 5:
            self.running = False
        return self.count >= 5


def open_socket():
    """
    the function open socket with the server and returns the socket and the message from the server
    :return: server socket, the message from the server
    :rtype: tuple
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create socket with the server
    server_address = (SERVER_IP, SERVER_PORT)
    server_sock.connect(server_address)
    server_msg = server_sock.recv(RECV)  # receive the message from the server (the welcome message)
    server_msg = server_msg.decode()
    return server_sock, server_msg

def sniff():
    """
    the function activates the sniffing
    :return: None
    """
    sniffer = Sniffer()

    print("[*] Start sniffing...")
    sniffer.start()

    while sniffer.running:
        print(sniffer.count)
        sleep(1)
        sniffer.count += 1

    print("[*] Stop sniffing")
    sniffer.join()

def scan_wifi_networks():
    """
    Scans for available WiFi networks using the netsh command on Windows.
    Returns a list of SSIDs.
    :return: None
    """
    try:
        result = subprocess.run(["netsh", "wlan", "show", "network"], capture_output=True, text=True, check=True)
        output = result.stdout

        # Use regular expression to extract SSIDs
        ssids = re.findall(r"SSID \d+ : (.+)", output)

        return ssids
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def show_available_networks():
    """
    Displays the list of available WiFi networks.
    :return: None
    """
    networks = scan_wifi_networks()

    if isinstance(networks, list):
        print("Available Networks:")
        for ssid in networks:
            print(ssid)
    else:
        print(networks)


def connect_to_wifi(ssid, password):
    """
    Connects to a WiFi network using pywifi.
    :param ssid: SSID of the WiFi network.
    :type: string
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
        if result.ssid == ssid:
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
            print(f"Successfully connected to {ssid}")
        else:
            print(f"Failed to connect to {ssid}")
    else:
        print(f"Network {ssid} not found in scan results")


def main():
    server_sock, server_msg = open_socket()
    print(server_msg)  # print the welcome message from the server

    sniff()

    server_sock.close()


if(__name__ == "__main__"):
    main()






