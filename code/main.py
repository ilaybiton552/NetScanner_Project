from scapy.all import *
from threading import Thread
from time import sleep


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


sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

while sniffer.running:
    print(sniffer.count)
    sleep(1)
    sniffer.count += 1

print("[*] Stop sniffing")
sniffer.join()
