from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

DST_IP = '192.168.68.62'

def main():
    message = input("Enter your message: ")
    len_message =len(message)
    
    for index, char in enumerate(message):
        ascii_presentation = ord(char)

        message_packet = IP(dst = DST_IP)/UDP(sport = 24601,dport = ascii_presentation, chksum = index, len = len_message)
        send(message_packet)

if __name__ == "__main__":
    main()