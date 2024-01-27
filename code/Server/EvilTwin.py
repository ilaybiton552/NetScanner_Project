from scapy.all import sniff, Dot11

class EvilTwinDetector:
    def __init__(self):
        self.access_points = {}

    def add_access_point(self, ssid, bssid):
        if ssid not in self.access_points:
            self.access_points[ssid] = []
        self.access_points[ssid].append({'bssid': bssid})
        self.detect_evil_twin(ssid, self.access_points[ssid])

    def detect_evil_twin(self, ssid, access_points):
        if len(access_points) > 1:
            print(f"Possible Evil Twin detected! SSID: {ssid}")

def packet_handler(packet, detector):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 8:
            ssid = packet.info.decode()
            bssid = packet.addr2
            detector.add_access_point(ssid, bssid)
