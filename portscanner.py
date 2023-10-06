from scapy.all import *
import argparse
import threading
from queue_structure import Queue

def getArgs():
    parser = argparse.ArgumentParser(
        prog="Port Sniper",
        description="A simple and efficient TCP port-scanner"
        )

    parser.add_argument('-i','--ip', 
                        type=str, 
                        help='The machine IP to scan', 
                        dest='ip', 
                        required=True)

    parser.add_argument('-p','--port', 
                        type=str, 
                        help='Port range to scan seperated by a dash, ex: 80 or 1-100', 
                        dest='port', 
                        required=True)

    args = parser.parse_args()

    return args



def QueuePorts():
    args = getArgs()
    split_args = args.port.split('-')
    portQueue = Queue()
    for port in range(int(split_args[0]), int(split_args[1]) + 1):
        portQueue.enqueue(port)
    return portQueue

def synScan(ip, port):
    syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')
    rest_packet = IP(dst=ip)/TCP(dport=port, flags='R')
    response = sr1(syn_packet, verbose=0, timeout=5).sprintf("%TCP.flags%")
    if response == 'SA':
        print(f"Port {port} on {ip} is open")
        send_rest = sr1(rest_packet, verbose=0,timeout=1)
        
    elif response== 'RA':
        print(f"Port {port} on {ip} is closed")
        

def main():
    args = getArgs()
    portQueue = QueuePorts()
    while not portQueue.isEmpty():
        port = portQueue.dequeue()
        synScan(args.ip, port)

# main()

synScan("192.168.1.1", 1)

# TO-DO
# Figure out how to run different scan functions depending on scan flag argument we will make (if statements? lame)
# Threading
# Different scans with scapey

# Bugs
# 192.168.1.1 works but 192.168.1.12 gives an error? wtf?

# https://thepacketgeek.com/scapy/building-network-tools/part-10/#sweep-and-scan

# synScan('192.168.1.1', 443)