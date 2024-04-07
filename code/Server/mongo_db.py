import pymongo

users = None
scan_results = None
attacks = None
blocked_comp = None

#region User
class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = password

    def insert(self):
        users.insert_one({'username': self.username, 'email': self.email, 'password': self.password})

    def update(self):
        users.update_one({'username': self.username}, {'$set': {'email': self.email, 'password': self.password}})

    def delete(self):
        users.delete_one({'username': self.username})

    @staticmethod
    def get_all():
        return users.find()

    @staticmethod
    def get_by_username(username):
        return users.find_one({'username': username})
    
    @staticmethod
    def check_duplicate(username):
        for user in users.find({'username': username}):
            if user:
                return True
        return False
    
    @staticmethod
    def login(username, password):
        user = users.find_one({'username': username, 'password': password})
        if user:
            return True
        return False
#endregion    

#region Attack
class Attack:
    def __init__(self, attack_name, attack_description):
        self.attack_name = attack_name
        self.attack_description = attack_description
    
    def insert(self):
        attacks.insert_one({'attack_name': self.attack_name, 'attack_description': self.attack_description})
    
    def delete(self):
        attacks.delete_one({'attack_name': self.attack_name})
    
    def update(self):
        attacks.update_one({'attack_name': self.attack_name}, {'$set': {'attack_description': self.attack_description}})
    
    @staticmethod
    def get_all():
        return attacks.find()
    
    @staticmethod
    def create_collection():
        attacks.find()
        for attack in attacks.find():
            if attack: return # Collection already exists
            else: continue # Collection does not exist

        attacks.insert_many([
            {"attack_name": "ARP Spoofing", "attack_description": "ARP spoofing is a technique by which an attacker sends (or 'poisons') the Address Resolution Protocol (ARP) cache of a target system. It is a type of attack in which the attacker sends fake ARP messages over a local area network."},
            {"attack_name": "DNS Poisoning", "attack_description": "DNS poisoning, also referred to as DNS cache poisoning, is a form of computer security hacking in which corrupt Domain Name System data is introduced into the DNS resolver's cache, causing the name server to return an incorrect IP address."},
            {"attack_name": "Evil Twin", "attack_description": "An evil twin is a fraudulent Wi-Fi access point that appears to be legitimate but is set up to eavesdrop on wireless communications. The evil twin is the wireless LAN equivalent of the phishing scam."},
            {"attack_name": "SMURF", "attack_description": "A smurf attack is a distributed denial-of-service attack in which large numbers of Internet Control Message Protocol (ICMP) packets with the intended victim's spoofed source IP are broadcast to a computer network using an IP broadcast address."},
            {"attack_name": "SYN Flood", "attack_description": "A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic."}
        ])
#endregion
      
#region ScanResult
class ScanResult:
    def __init__(self, username, security_attack, scan_date, mac_address, ip_address, ssid):
        self.username = username
        self.security_attack = security_attack
        self.scan_date = scan_date
        self.mac_address = mac_address
        self.ip_address = ip_address
        self.ssid = ssid
       
    def insert(self):
        scan_results.insert_one({'username': self.username, 'security_attack': self.security_attack, 'scan_date': self.scan_date, 'mac_address': self.mac_address, 'ip_address': self.ip_address, 'ssid': self.ssid})

    @staticmethod
    def get_all():
        return scan_results.find()
        
    @staticmethod
    def get_by_username(username):
        return scan_results.find({'username': username})

#endregion        

#region BlockedComp
    class BlockedComp:
        def __init__(self, mac_address, ip_address, attack):
            self.mac_address = mac_address
            self.ip_address = ip_address
            self.attack = attack
        
        def insert(self):
            blocked_comp.insert_one({'mac_address': self.mac_address, 'ip_address': self.ip_address, 'attack': self.attack})
        
        @staticmethod
        def get_all():
            return blocked_comp.find()
#endregion

def create_database():
    global users
    global scan_results
    global attacks
    global blocked_comp
    client = pymongo.MongoClient('localhost', 27017)
    db = client.neuraldb
    users = db.users
    scan_results = db.scan_results
    attacks = db.attacks
    blocked_comp = db.blocked_comp
    Attack.create_collection()

def add_info():
    user = User('admin', 'admin@gmail,com', 'admin')
    user.insert()
    user = User('user', 'user@gmail,com', 'user')
    user.insert()
    user = User('user2', 'user2@gmail,com', 'user2')
    user.insert()

    scan_result = ScanResult('admin', 'ARP Spoofing', '2021-09-01', '00:00:00:00:00:00', '123.34.5.2', 'wow', 'some')
    scan_result.insert()
    scan_result = ScanResult('admin', 'DNS Poisoning', '2021-09-02', '00:00:00:00:00:01', '233.23.4.2', 'cat', 'some')
    scan_result.insert()
    scan_result = ScanResult('admin', 'Evil Twin', '2021-09-03', '00:00:00:00:00:02', '23.22.34.2', 'kiko milano', 'some2')
    scan_result.insert()

    blocked_comp.insert_many([{ 'mac_address': '00:00:00:00:00:00', 'ip_address': '134.21.46.3', 'attack': 'Evil Twin'}, { 'mac_address': '00:00:00:00:00:01', 'ip_address': '121.21.46.3', 'attack': 'ARP Spoofing' }, { 'mac_address': '00:00:00:00:00:02', 'ip_address': '23.21.46.3', 'attack': 'DNS Poisoning' }])

def main():
    create_database()
    add_info()
    
    #use the database here

if __name__ == '__main__':
    main()
