import subprocess
from scapy.all import sniff, Dot11
import netifaces
import re
from threading import Thread 

class EvilTwin(Thread):
    def __init__(self, interface):
        Thread.__init__(self)
        self.interface = interface
        self.networks = {}
        self.running = True

    def run(self):
        self.enable_monitor_mode()
        self.exc = None
        try:
            sniff(iface=self.interface, prn=self.handle_packet, stop_filter=self.stop)
        except Exception as ex:
            self.exc = ex
        finally:
            if (self.interface != "mon0"):
                self.disable_monitor_mode()
            print("Sniffing stopped.")
    
    def join(self):
        Thread.join(self)
        if self.exc:
            raise self.exc

    def stop(self, packet):
        return not self.running

    def handle_packet(self, packet):
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:
                ssid = packet.info.decode()
                bssid = packet.addr3
                print(f"Network detected: {ssid} ({bssid})")
                if ssid in self.networks:
                    if bssid != self.networks[ssid][0]:
                        print(f"Warning: Multiple access points detected for network '{ssid}'. This could be an evil twin attack.")
                else:
                    self.networks[ssid] = [bssid]
                    print(f"Network '{ssid}' added to list of known networks.")

    def enable_monitor_mode(self): 
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", self.interface, "mode", "monitor"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)
        print("Enable monitor mode")

    def disable_monitor_mode(self):
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "down"], check=True)
        subprocess.run(["sudo", "iwconfig", self.interface, "mode", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], check=True)
        print("Disable monitor mode")

if __name__ == "__main__":
    interfaces = netifaces.interfaces()
    print("Available network interfaces:", interfaces[1])
    interface = input("Enter network interface to use: ")
    try:
        evil_twin_detector = EvilTwin(interface)
        evil_twin_detector.start()
        evil_twin_detector.join()

    except Exception as ex:
        print("Stopped the sniffing because: ", ex)