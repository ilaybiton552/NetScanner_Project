import scanningDevice
from loginRequest import *
from flask import Flask, request, jsonify
from flask_cors import CORS


app = Flask(__name__)
CORS(app)

@app.route('/networks', methods=['GET'])
def get_available_networks():
    try:
        networks = scanningDevice.Network.scan_wifi_networks()
        network_dicts = [network.to_dict() for network in networks]
        return jsonify(network_dicts)
    except Exception as e:
        return jsonify({'Error': str(e)}), 500


@app.route('/networks', methods=['POST'])
def connect_to_network():
    try:
        request_data = request.json
        ssid = request_data.get('ssid')
        password = request_data.get('password')

        if not ssid or not password:
            return jsonify({'error': 'SSID and password are required'})

        networks = scanningDevice.Network.scan_wifi_networks()
        network = list(filter(lambda network: network.ssid == ssid, networks))
        if network:
            network[0].connect_to_network(password)
            return jsonify({'Message': f'Connected successfully to {ssid} with the provided password'})
        else:
            return jsonify({'Error': f'Network {ssid} not found'}), 404

    except Exception as e:
        return jsonify({'Error': str(e)}), 500


@app.route('/start_scan', methods=['POST'])
def start_scanning():
    args = request.json
    dns_poisoning = args.get('dns_poisoning')
    syn_flood = args.get('syn_flood')
    arp_spoofing = args.get('arp_spoofing')
    smurf = args.get('smurf')
    evil_twin = args.get('evil_twin')

    scanningDevice.start_sniffing(dns_poisoning, syn_flood, arp_spoofing, smurf)
    msg = "start scanning for:\n"
    if dns_poisoning:
        msg += "DNS Poisoning\n"
    if syn_flood:
        msg += "SYN Flood\n"
    if arp_spoofing:
        msg += "ARP Spoofing\n"
    if smurf:
        msg += "SMURF\n"
    if evil_twin:
        msg += "Evil Twin\n"
    return jsonify({"Message": msg})


@app.route('/stop_scan')
def stop_scanning():
    scanningDevice.stop_sniffing()
    return jsonify({"Message":"stop scanning"})


def main():
    # Run the server on http://localhost:5000
    app.run(debug=True)


if __name__ == '__main__':
    main()
