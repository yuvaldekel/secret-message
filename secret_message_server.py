from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

SRC_IP = 24601

def get_message(packet):
    return (UDP in packet and packet[UDP].sport == SRC_IP)

def find_missing_packets(l):
    l = [i[1] for i in l]
    
    missing = []
    length = len(l)
    indexes = [i for i in range(length)]
    indexes[-1] = 999
    
    for index_1 , index_2 in zip(l, indexes):
        if index_2 != index_1:
            missing.append(index_2)
    return missing

def main():
    index = 0
    message_chars =[]
    while index != 999:
        packet = sniff(lfilter = get_message)
        ascii = packet[UDP].dport
        index = packet[UDP].chksum
        message_chars.append((chr(ascii), index))

    message_chars.sort(key = lambda x: x[1])
    
    message = ''.join([char[0] for char in message_chars])
    print(message)

if __name__ == "__main__":
    main()