import subprocess
import threading
import schedule
import time

stop_threads = False

class AccessPoint:
    def __init__(self, ssid, mac_address):
        self.ssid = ssid
        self.mac_address = mac_address

    def __str__(self):
        return f"SSID: {self.ssid}, BSSID: {self.mac_address}"

def to_dict_from_output(output):
    access_points = []
    lines = output.split('Cell')
    address = None
    ssid = None
    for line in lines:
        for line in line.split('\n'):
            if "Address" in line:
                address = line.split()[3]
            elif "ESSID" in line:
                ssid = line.split()
                ssid = ssid[0].split("ESSID:").pop().replace('"', '')
            if address and ssid:
                access_points.append(AccessPoint(ssid, address))
                address = None
                ssid = None
    
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
            return to_dict_from_output(output)
        
        else:
            print("No wireless interface found.")

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")


def job():
    access_points = scan_wireless_access_points()
    ssid_counts = {}
    for ap in access_points:
        if ap.ssid in ssid_counts:
            ssid_counts[ap.ssid] += 1
        else:
            ssid_counts[ap.ssid] = 1

    duplicates = [ssid for ssid, count in ssid_counts.items() if count > 1]
    if duplicates:
        print(f"Evil twin detected with SSIDs: {', '.join(duplicates)}")


def main_thread_job(stop_threads):
    schedule.every(10).seconds.do(job)

    while stop_threads:
        schedule.run_pending()
        time.sleep(1)

def starting_evil_twin_detection():
    stop_threads = False
    main_thread = threading.Thread(target=main_thread_job, args=(lambda: stop_threads(),))
    main_thread.start()
    main_thread.join()

def finishing_evil_twin_detection():
    stop_threads = True
    