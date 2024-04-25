from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

CLIENT_IP = '192.168.68.65'
SERVER_IP = '192.168.68.62'

def send_packet(packet):
    acknowledge = sr1(packet, timeout = 5)
    if acknowledge != None:
        return False
    else:
        print('packet did not arrive')
        return True

def main():
    message = input("Enter your message: ")
    
    for index, char in enumerate(message):
        ascii_presentation = ord(char)

        print(f"sending {char} to port {ascii_presentation}")

        message_packet = IP(dst = SERVER_IP, src = CLIENT_IP)/UDP(sport = 24601,dport = ascii_presentation, chksum = index + 1)
        
        continue_sent = True
        i = 0
        while continue_sent and i < 10:
            continue_sent = send_packet(message_packet)
            i = i + 1

    
    print("sending end message")

    end_packet = IP(dst = SERVER_IP, src = CLIENT_IP)/UDP(sport = 24601,dport = 4)

    continue_sent = True    
    i = 0
    while continue_sent and i < 10:    
        continue_sent = send_packet(end_packet)
        i = i + 1
        
if __name__ == "__main__":
    main()