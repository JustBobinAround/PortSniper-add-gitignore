class Scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    
    def ip(self):
        return self.ip
    
    def port(self):
        return self.port
    
    def ping(self):
        ping_packet = IP(dst=ip)/ICMP()
        ping_response = sr1(ping_packet, timeout=1, verbose=0)
        return ping_response