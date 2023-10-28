from scapy.all import *


def print_packet(packet):
    """
    the function prints the summary of a packet
    :param packet: the packet to print
    :return: None
    """
    print(packet.summary())


def main():
    print("welcome to sniffing prototype:")

    try:
        sniff(lfilter=print_packet)  # do the sniffing
    except Exception:
        print("the sniffing stopped")


if __name__ == '__main__':
    main()
