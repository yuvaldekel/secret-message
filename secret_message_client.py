from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

DST_IP = '127.0.0.1'

def main():
    message = input("Enter your message: ")
    for index, char in enumerate(message):
        ascii_presentation = ord(char)
        message_packet = IP(dst = DST_IP)/UDP(sport = 24601,dport = ascii_presentation, chksum = index)
        send(message_packet)

if __name__ == "__main__":
    main()