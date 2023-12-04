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


def start_scanning():
    """
    Starts the scanning of the device
    :return: None
    """
    response = requests.get('http://localhost:5000/start_scan')
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


def main():
<<<<<<< HEAD
    get_available_networks()
    ssid = input("Enter the name of network that you want to connect to: ")
    password = input("Enter the password to that network")
    connect_to_network(ssid, password)
=======
    try:
        get_available_networks()
        ssid = input("Enter the name of network that you want to connect to: ")
        password = input("Enter the password to that network: ")
    except Exception as ex:
        print(ex)
    try:
        while True:
            start_scanning()
            stop = input()
            while stop != 'stop':
                stop = input()
            stop_scanning()
    except Exception as ex:
        print(ex)

>>>>>>> d55f854f2812a726bb0966eb4f30e38a75171ac4

if __name__ == '__main__':
    main()
