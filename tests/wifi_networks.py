import subprocess, platform, re

def list_open_networks():
    # Get the name of the operating system.
    os_name = platform.system()
    # Check if the OS is Linux.
    if os_name == "Linux":
        # Command to list Wi-Fi networks on Linux.
        list_networks_command = "nmcli -t -f ssid dev wifi"
        try:
            # Execute the command and capture the output.
            output = subprocess.check_output(list_networks_command, shell=True, text=True)
            networks = []
            # Parse the output to find Wi-Fi networks.
            for line in output.splitlines():
                # Extract the SSID (Wi-Fi network name).
                ssid = line.strip()
                networks.append(ssid)
            return networks
        except subprocess.CalledProcessError as e:
            print(f"An error occurred: {e}")
    else:
        print("This function only works on Linux.")

# Test the function
networks = list_open_networks()
if networks:
    print("Available networks:")
    for network in networks:
        print(network)