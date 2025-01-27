from scapy.all import *
from rich import print as rprint

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
        try:
            self.ping_response = sr1(self.ping_packet, timeout=1, verbose=0)
            return self.ping_response
        except:
            rprint("[bold red]Error: Scan requires sudo, exiting....")
            exit()
    
    def syn(self):
        self.syn_packet = IP(dst=self.ip)/TCP(dport=self.port, flags='S')
        self.rest_packet = IP(dst=self.ip)/TCP(dport=self.port, flags='R')
        self.response = sr1(self.syn_packet, verbose=0, timeout=1)

        self.responeFlag = self.response.sprintf("%TCP.flags%")

        if self.responeFlag == 'SA':
            sr1(self.rest_packet, verbose=0,timeout=1)

        return self.response