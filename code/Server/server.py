import scanningDevice
from loginRequest import *
from flask import Flask, request, jsonify


app = Flask(__name__)

@app.route('/networks', methods=['GET'])
def get_available_networks():
    networks = scanningDevice.Network.scan_wifi_networks()
    network_dicts = [network.to_dict() for network in networks]
    return jsonify(network_dicts)


@app.route('/start_scan')
def start_scanning():
    scanningDevice.start_sniffing()
    return "start scanning"


@app.route('/stop_scan')
def stop_scanning():
    scanningDevice.stop_sniffing()
    return "stop scanning"


def main():
    # Run the server on http://localhost:5000
    """
    scanningDevice.show_available_networks()
    ssid = input("Enter the network ssid you want to connect to: ")
    password = input("Enter the password to that network: ")
    networks = scanningDevice.Network.scan_wifi_networks()
    network = list(filter(lambda network: network.ssid == ssid, networks))
    network[0].connect_to_network(password)
    """
    app.run(debug=True)


if __name__ == '__main__':
    main()
