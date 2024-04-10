from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

DST_IP = '192.168.68.60'
SRC_IP = '192.168.68.62'

def send_packet(packet):
    acknowledge = sr1(packet, timeout = 5)
    try:
        acknowledge = acknowledge[0]
        return False
    except IndexError:
        print('packet did not arrive trying again ')
        return True

def main():
    message = input("Enter your message: ")
    
    for index, char in enumerate(message):
        ascii_presentation = ord(char)

        continue_sent = True
        message_packet = IP(dst = DST_IP, src = SRC_IP)/UDP(sport = 24601,dport = ascii_presentation, chksum = index - 1)
        
        continue_sent = send_packet(message_packet)
        i = 0
        while continue_sent and i <= 10:
            continue_sent = send_packet(message_packet)
            i = i + 1

    continue_sent = True
    end_packet = IP(dst = DST_IP, src = SRC_IP)/UDP(sport = 24601,dport = 4)
    
    continue_sent = send_packet(end_packet)
    while continue_sent and i <= 10:
        i = 0
        continue_sent = send_packet(end_packet)
        i = i + 1
        

if __name__ == "__main__":
    main()