from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

DST_IP = '192.168.68.62'
SRC_IP = '192.168.68.60'

def send_packet(packet):
    acknowledge = sr1(message_packet, timeout = 5)
    try:
        acknowledge = acknowledge[0]
        continue_sent = False
    except IndexError:
        print('packet did not arrive trying again ')
        raise IndexError

def main():
    message = input("Enter your message: ")
    
    for index, char in enumerate(message):
        ascii_presentation = ord(char)

        continue_sent = True
        message_packet = IP(dst = DST_IP, src = SRC_IP)/UDP(sport = 24601,dport = ascii_presentation, chksum = index)

        while continue_sent:
            acknowledge = sr1(message_packet, timeout = 5)
            try:
                acknowledge = acknowledge[0]
                continue_sent = False
            except IndexError:
                print('packet did not arrive trying again ')

    continue_sent = True
    end_packet = IP(dst = DST_IP, src = SRC_IP)/UDP(sport = 24601,dport = 4)
    acknowledge = sr1(end_packet, timeout = 5)
    try:
        acknowledge = acknowledge[0]
        continue_sent = False
    except IndexError:
        print('packet did not arrive trying again ')
    while continue_sent:
        acknowledge = sr1(end_packet, timeout = 5)
        try:
            acknowledge = acknowledge[0]
            continue_sent = False
        except IndexError:
            print('packet did not arrive trying again ')    

if __name__ == "__main__":
    main()