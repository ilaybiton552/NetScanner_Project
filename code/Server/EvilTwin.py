from scapy.all import *
import pywifi

class EvilTwinDetector:
    def __init__(self, interface):
        self.interface = interface
        self.access_points = {}

    def handle_beacon(self, packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr3
            ssid = packet[Dot11Elt].info.decode("utf-8", "ignore")
            channel = int(ord(packet[Dot11Elt:3].info))
            signal_strength = -(256 - ord(packet.notdecoded[-4:-3]))

            self.update_access_points(bssid, ssid, channel, signal_strength)

    def update_access_points(self, bssid, ssid, channel, signal_strength):
        if bssid not in self.access_points:
            self.access_points[bssid] = {'SSID': ssid, 'Channel': channel, 'SignalStrength': signal_strength}
        else:
            # Update the information if the access point is already known
            self.access_points[bssid]['SSID'] = ssid
            self.access_points[bssid]['Channel'] = channel
            self.access_points[bssid]['SignalStrength'] = signal_strength

    def detect_evil_twin(self):
        for bssid, info in self.access_points.items():
            ssid = info['SSID']
            channel = info['Channel']
            signal_strength = info['SignalStrength']

            # Advanced approach 1: Identify open networks (no encryption) posing as secured networks
            if ssid.startswith("SecuredNetwork") and not self.is_network_encrypted(bssid):
                print(f"Possible Evil Twin detected - Open network posing as secured - BSSID: {bssid}, SSID: {ssid}, Channel: {channel}, Signal Strength: {signal_strength} dBm")

            # Advanced approach 2: Detect changes in channel over a short period (possible hopping Evil Twin)
            if self.channel_hopping_detected(bssid, channel):
                print(f"Possible Evil Twin detected - Channel hopping - BSSID: {bssid}, SSID: {ssid}, Channel: {channel}, Signal Strength: {signal_strength} dBm")

            # Add more advanced approaches as needed...

    def is_network_encrypted(self, bssid):
        encrypted = False
        try:
            # Send a probe request to the target BSSID and capture the response
            probe_req = RadioTap()/Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=RandMAC(), addr3=bssid)/Dot11ProbeReq()
            probe_res = srp1(probe_req, iface=self.interface, timeout=1)

            # Check if the response contains the RSN information element
            if probe_res and probe_res.haslayer(Dot11Elt):
                rsne = probe_res[Dot11Elt][Dot11Elt][2]
                if rsne == b'\x30\x18\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x04\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x02\x04\x00':
                    encrypted = True
        except Exception as e:
            print(f"Error checking encryption for {bssid}: {str(e)}")

        return encrypted

    def channel_hopping_detected(self, bssid, current_channel):
        try:
            # Monitor the channel on which the Evil Twin is broadcasting
            channel_before = None

            def sniff_callback(pkt):
                nonlocal channel_before
                if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr3 == bssid:
                    current_channel = ord(pkt[Dot11Elt][Dot11Elt].info[2])
                    if channel_before is not None and current_channel != channel_before:
                        print(f"Channel hopping detected for {bssid} (Channel {channel_before} to {current_channel})")
                        return True
                    channel_before = current_channel

            # Start sniffing on the specified interface
            sniff(iface=self.interface, prn=sniff_callback, timeout=60)

        except Exception as e:
            print(f"Error detecting channel hopping for {bssid}: {str(e)}")

        return False
