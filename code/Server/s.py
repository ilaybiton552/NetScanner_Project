import subprocess

def get_self_ip_address():
    ip_address = subprocess.check_output(['hostname', '-I']).decode().strip().split(' ')[0]
    print(ip_address)
    return ip_address

