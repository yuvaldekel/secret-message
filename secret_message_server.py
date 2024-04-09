from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

SRC_PORT = 24601
SRC_IP = '192.168.68.60'

def get_message(packet):
    return (IP in packet and packet[IP].src == SRC_IP and UDP in packet and packet[UDP].sport == SRC_IP)

def find_missing_packets(original_list):
    return [num for num in range(len(original_list)) if num not in original_list]

def main():
    len_message = 1
    i = 0
    message =[]
    while i < len_message:
        packet = sniff(count = 1, lfilter = get_message, timeout= 10)
        try:
            ascii = packet[0][UDP].dport
            index = packet[0][UDP].chksum
            len_message = packet[0][UDP].len
            message.append((chr(ascii), index))
            i = i + 1
        except IndexError:
            exit()

    message.sort(key = lambda x: x[1])
    
    missing = find_missing_packets(message)

    message = ''.join(['*' if i in missing else char[0] for i, char in enumerate(message)])
    print(message)

if __name__ == "__main__":
    main()