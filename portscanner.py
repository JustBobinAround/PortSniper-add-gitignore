import scapy
import argparse

def getArgs():
    parser = argparse.ArgumentParser(
        prog="Port Sniper",
        description="A simple and efficient port-scanner"
        )

    parser.add_argument('-i','--ip', type=str, help='The machine IP to scan', dest='ip', required=True)
    parser.add_argument('-p','--port', type=str, help='Port range to scan seperated by a dash, ex: 80 or 1-100', dest='port', required=True)

    args = parser.parse_args()

    return args


args = getArgs()
print(args.ip, args.port)