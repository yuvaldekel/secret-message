from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

SRC_PORT = 24601
SRC_IP = '192.168.68.62'
MY_IP = '192.168.68.60'

def get_message(packet):
    return (IP in packet and packet[IP].src == SRC_IP and UDP in packet and packet[UDP].sport == SRC_PORT)

def find_missing_packets(original_list):
    original_list = [i[1] for i in original_list]
    return [num for num in range(len(original_list)) if num not in original_list]

def main():
    message =[]
    while True:
        packet = sniff(count = 1, lfilter = get_message)
 
        ascii = packet[0][UDP].dport
        index = packet[0][UDP].chksum -1 
        acknowledge_packet = IP(dst = SRC_IP, src = MY_IP)/UDP(sport = ascii,dport = 24601)
        send(acknowledge_packet)
        if ascii == 4:
            break

        message.append((chr(ascii), index))

    #message.sort(key = lambda x: x[1])
    message = list(set(message))
    missing = find_missing_packets(message)

    message = ''.join(['~' if i in missing else char[0] for i, char in enumerate(message)])

if __name__ == "__main__":
    main()
