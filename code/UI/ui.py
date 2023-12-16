import requests
import json

def check_request(response):
    """
    Checks if the request was successful
    :param response: the response of the request
    :return: none, raise an exception if not
    """
    # Check if the request wasn't successful (status code 200)
    if response.status_code != 200:
        # Raise an error message if the request was not successful
        raise Exception(f"Error: {response.status_code} - {response.text}")


def get_available_networks():
    response = requests.get('http://localhost:5000/networks')
    check_request(response)
    # Print the cat information
    network_info = response.json()
    for network in network_info:
        print(f"SSID: {network['ssid']}, Network type: {network['network_type']}, Authentication: {network['authentication']}, Encryption: {network['encryption']}")


def start_scanning(dns_poisoning, syn_flood, arp_spoofing):
    """
    Starts the scanning of the device
    :return: None
    """
    request_msg = 'http://localhost:5000/start_scan?dns_poisoning={dns}&syn_flood={{syn}}&arp_spoofing={{{{arp}}}}'
    if dns_poisoning:
        request_msg = request_msg.format(dns=1)
    else:
        request_msg = request_msg.format(dns='')
    if syn_flood:
        request_msg = request_msg.format(syn=1)
    else:
        request_msg = request_msg.format(syn='')
    if arp_spoofing:
        request_msg = request_msg.format(arp=1)
    else:
        request_msg = request_msg.format(arp='')
    response = requests.get(request_msg)
    check_request(response)
    print(response.text)


def stop_scanning():
    """
    Stops the scanning of the device
    :return: None
    """
    response = requests.get('http://localhost:5000/stop_scan')
    check_request(response)
    print(response.text)


def connect_to_network(ssid, password):
    url = 'http://localhost:5000/networks'
    network_info = {'ssid': ssid, 'password': password}
    response = requests.post(url, json=network_info)
    if response.status_code == 200:
        print(response.json())
    else:
        print(response.json())


def get_yes_no_input(message):
    """
    Gets y/n input from the user
    :param message: the message for the input
    :return: bool, True for yes ('y'), False for no ('n)
    """
    user_input = input(message)
    while user_input != 'y' and user_input != 'n':
        user_input = input(message)
    if user_input == 'y':
        return True
    return False



def main():
    connect_wifi = get_yes_no_input("Would you like to connect to WIFI? (y/n): ")
    if connect_wifi:
        try:
            get_available_networks()
            ssid = input("Enter the name of network that you want to connect to: ")
            password = input("Enter the password to that network: ")
            connect_to_network(ssid, password)
        except Exception as ex:
            print(ex)
    start_scan = get_yes_no_input("Would you like to start scanning? (y/n): ")
    if start_scan:
        try:
            while True:
                scan = input("To stop scan press s, to start scan press any key: ")
                if scan == 's':
                    stop_scanning()
                else:
                    dns_poisoning = get_yes_no_input("Filter for DNS Poisoning attack? (y/n): ")
                    syn_flood = get_yes_no_input("Filter for SYN Flood attack? (y/n): ")
                    arp_spoofing = get_yes_no_input("Filter for ARP Spoofing attack? (y/n): ")
                    start_scanning(dns_poisoning, syn_flood, arp_spoofing)
        except Exception as ex:
            print(ex)


if __name__ == '__main__':
    main()
