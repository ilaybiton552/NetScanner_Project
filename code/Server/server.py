import scanningDevice
from loginRequest import *
from flask import Flask, request, jsonify
from flask_cors import CORS
import platform
import network_scan
import mongo_db

app = Flask(__name__)
CORS(app)

@app.route('/networks', methods=['GET'])
def get_available_networks():
    try:
        os_name = platform.system() # Get the name of the operating system.
        print(os_name)

        if os_name == "Windows":
            networks = scanningDevice.Network.scan_wifi_networks()
            network_dicts = [network.to_dict() for network in networks]
            return jsonify(network_dicts)
        
        elif os_name == "Linux":
            networks = scanningDevice.Network.scan_wireless_access_points()
            network_dicts = [network.to_dict() for network in networks]
            return jsonify(network_dicts)
        
        else:
            print("Unsupported OS")
            return jsonify({'Error': 'Unsupported OS'}), 500
    except Exception as e:
        return jsonify({'Error get networks server': str(e)}), 500


@app.route('/networks', methods=['POST'])
def connect_to_network():
    try:
        os_name = platform.system() # Get the name of the operating system.

        if os_name == "Windows":
            request_data = request.json
            ssid = request_data.get('ssid')
            password = request_data.get('password')

            if not ssid or not password:
                return jsonify({'error': 'SSID and password are required'})

            networks = scanningDevice.Network.scan_wifi_networks()
            network = list(filter(lambda network: network.ssid == ssid, networks))
            if network:
                connect = network[0].connect_to_network(password)
                if(connect):
                    return jsonify({'Message': f'Connected successfully to {ssid} with the provided password'})
                else:
                    return jsonify({'Message': f'Error with connecting, wrong password'}), 404
            else:
                return jsonify({'Error': f'Network {ssid} not found'}), 404
            
        elif os_name == "Linux":
            request_data = request.json
            ssid = request_data.get('ssid')
            password = request_data.get('password')

            if not ssid or not password:
                return jsonify({'error': 'SSID and password are required'})

            networks = scanningDevice.Network.scan_wireless_access_points()
            network = list(filter(lambda network: network.ssid == ssid, networks))
            if network:
                connect = network[0].connect_to_wifi(password)
                if(connect):
                    return jsonify({'Message': f'Connected successfully to {ssid} with the provided password'})
                else:
                    return jsonify({'Message': f'Error with connecting, wrong password'}), 404
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

    scanningDevice.start_sniffing(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin)
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


@app.route('/update_scan', methods=['POST'])
def update_scanning():
    args = request.json
    dns_poisoning = args.get('dns_poisoning')
    syn_flood = args.get('syn_flood')
    arp_spoofing = args.get('arp_spoofing')
    smurf = args.get('smurf')
    evil_twin = args.get('evil_twin')

    try:
        scanningDevice.update_sniffer(dns_poisoning, syn_flood, arp_spoofing, smurf, evil_twin)
        msg = "update scanning for:\n"
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
    except Exception as ex:
        return jsonify({"Error": "error"})


@app.route('/network_state', methods=['GET'])
def get_network_state():
    try:
        computers = network_scan.get_network_state()
        computers_dict = [computer.to_dict() for computer in computers]
        print(computers_dict)
        return jsonify(computers_dict)
    except Exception as e:
        return jsonify({'Error': str(e)}), 500
    

@app.route('/scan_state', methods=['GET'])
def get_scan_state():
    return jsonify(scanningDevice.get_scan_state())

@app.route('/all_attacks', methods=['GET'])
def get_all_attacks():
    attacks = mongo_db.Attack.get_all()
    attacks_dict = list(attacks)
    for attack in attacks_dict:
        del attack['_id']
    return jsonify({attacks_dict})

@app.route('/all_scan_results', methods=['GET'])
def get_all_scan_results():
    scan_results = mongo_db.ScanResult.get_all()
    scan_results_dict = list(scan_results)
    for scan_result in scan_results_dict:
        del scan_result['_id']
    return jsonify(scan_results_dict)

@app.route('/scan_results', methods=['POST'])
def get_scan_results_by_username():
    username = request.json.get('username')
    scan_results = mongo_db.ScanResult.get_by_username(username)
    scan_results_dict = list(scan_results)
    for scan_result in scan_results_dict:
        del scan_result['_id']
    return jsonify(scan_results)

@app.route('/login', methods=['POST'])
def login():
    print("login")
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')
    if not username or not password:
        return jsonify({'Error': 'Username and password are required'})
    if mongo_db.User.login(username, password):
        return jsonify({'Message': 'Login successful'})
    return jsonify({'Error': 'Login failed'}), 404

@app.route('/register', methods=['POST'])
def register():
    request_data = request.json
    username = request_data.get('username')
    password = request_data.get('password')
    email = request_data.get('email')
    if not username or not password:
        return jsonify({'Error': 'Username and password are required'})
    if mongo_db.User.check_duplicate(username):
        return jsonify({'Error': 'Username already exists'})
    user = mongo_db.User(username, email, password)
    user.insert()
    return jsonify({'Message': 'User created successfully'})
    

def main():
    # Run the server on http://localhost:5000
    mongo_db.create_database()
    app.run(debug=True)


if __name__ == '__main__':
    main()
