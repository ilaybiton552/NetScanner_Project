import subprocess
import threading
import schedule
import time
import mongo_db

NOTIFY_SCRIPT = "./notify.sh"
main_thread = None
stop_event = None


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
        msg = f"Evil twin detected with SSIDs: {', '.join(duplicates)}"
        print(msg)
        subprocess.run([NOTIFY_SCRIPT, msg])
        current_time = time.ctime(time.localtime())  # current time
        mongo_db.ScanResult(username, "Evil Twin", current_time, None, None, None).insert()  # insert the attack
        

def main_thread_job(stop_event):
    schedule.every(10).seconds.do(job)

    while not stop_event.is_set():
        schedule.run_pending()
        time.sleep(1)


def starting_evil_twin_detection(user):
    global username
    global stop_event
    global main_thread
    username = user
    stop_event = threading.Event()
    main_thread = threading.Thread(target=main_thread_job, args=(stop_event,))
    main_thread.start()


def finishing_evil_twin_detection():
    global stop_event
    if stop_event is not None:
        stop_event.set()
    