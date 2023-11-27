import requests
import json

def get_available_networks():
    response = requests.get('http://localhost:5000/networks')

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        # Print the cat information
        network_info = response.json()
        for network in network_info:
            print(f"SSID: {network['ssid']}, Network type: {network['network_type']}, Authentication: {network['authentication']}, Encryption: {network['encryption']}")
    else:
        # Print an error message if the request was not successful
        print(f"Error: {response.status_code} - {response.text}")


def main():
    get_available_networks()
    ssid = input("Enter the name of network that you want to connect to: ")
    password = input("Enter the password to that network")

if __name__ == '__main__':
    main()
