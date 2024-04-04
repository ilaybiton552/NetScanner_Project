import subprocess, platform, re



class AccessPoint:
    def __init__(self, ssid, network_type, authentication, encryption):
        self.ssid = ssid
        self.network_type = network_type
        self.authentication = authentication
        self.encryption = encryption

    def __str__(self):
        return f"SSID: {self.ssid}, Network Type: {self.network_type}, Authentication: {self.authentication}, Encryption: {self.encryption}"
    

def to_dict_of_networks_from_output(output):
    access_points = []
    lines = output.split('Cell')
    network_type = None
    authentication = None
    encryption = None
    ssid = None
    for line in lines:
        for line in line.split('\n'):
            if "ESSID" in line:
                ssid = line.split()
                ssid = ssid[0].split("ESSID:").pop().replace('"', '')
            elif "Authentication Suites" in line:
                authentication = line.split()[4]
            elif "Version" in line:
                network_type = line.split()[2]
            elif "Group Cipher" in line:
                encryption = line.split()[3]
            if ssid and authentication and network_type and encryption:
                if all(char == '\x00' for char in ssid):
                    ssid = " "
                access_points.append(AccessPoint(ssid, network_type, authentication, encryption))
                ssid = None
                authentication = None
                network_type = None
                encryption = None
    
    for access_point in access_points:
        print(access_point)

    return access_points


def scan_wireless_access_points():
    try:
        iwconfig_output = subprocess.check_output(['iwconfig'], universal_newlines=True)
        interface = next((line.split()[0] for line in iwconfig_output.split('\n') if 'ESSID' in line), None)
        print("Interface: ", interface)

        if interface:
            output = subprocess.check_output(['iwlist', interface, 'scan'], universal_newlines=True)
            # Process the output as needed
            return to_dict_of_networks_from_output(output)
        
        else:
            print("No wireless interface found.")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


def get_available_networks():
    result = subprocess.run(['sudo', 'iwlist', 'wlo1', 'scan'], capture_output=True, text=True)
    print(result.stdout)


def connect_to_wifi(ssid, password):
    try:
        subprocess.run(['nmcli', 'dev', 'wifi', 'connect', ssid, 'password', password], check=True)
        print(f"Connected to {ssid}")
    except subprocess.CalledProcessError:
        print(f"Failed to connect to {ssid}")
        

scan_wireless_access_points()
ssid = input("Enter the SSID: ")
password = input("Enter the password: ")
connect_to_wifi(ssid, password)