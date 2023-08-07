import scapy
import argparse
import threading
from queue_structure import Queue

def getArgs():
    parser = argparse.ArgumentParser(
        prog="Port Sniper",
        description="A simple and efficient port-scanner"
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

def main():
    portQueue = QueuePorts()
    portQueue.display()


# TO-DO
# Figure out how to run different scan functions depending on scan flag argument we will make (if statements? lame)
# Threading
# Different scans with scapey

main()