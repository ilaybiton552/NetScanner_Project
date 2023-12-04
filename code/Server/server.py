import scanningDevice
from loginRequest import *
from flask import Flask, request, jsonify


app = Flask(__name__)

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
    app.run(debug=True)


if __name__ == '__main__':
    main()
