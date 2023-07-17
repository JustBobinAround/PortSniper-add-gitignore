import scapy

src = "192.168.1.10"
dst = "72.14.207.99"
port = "80"

sr1(IP(dst=dst)/TCP(dport=port,flags="S"))