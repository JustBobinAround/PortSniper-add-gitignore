from scapy.all import *

class Scanner:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
    
    def ip(self):
        return self.ip
    
    def port(self):
        return self.port
    
   
    def ping(self):
        self.ping_packet = IP(dst=self.ip)/ICMP()
        self.ping_response = sr1(self.ping_packet, timeout=1, verbose=0)
        return self.ping_response