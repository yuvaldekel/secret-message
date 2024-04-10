from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR
from scapy.all import *

CLIENT_PORT = 24601
CLIENT_IP = '172.26.25.218'
SERVER_IP = '172.26.16.1'

def get_message(packet):
    return (IP in packet and packet[IP].src == CLIENT_IP and UDP in packet and packet[UDP].sport == CLIENT_PORT)

def find_missing_packets(original_list):
    original_list = [i[1] for i in original_list]
    return [num for num in range(len(original_list)) if num not in original_list]

def main():
    message =[]
    while True:
        packet = sniff(count = 1, lfilter = get_message)
 
        ascii = packet[0][UDP].dport
        index = packet[0][UDP].chksum -1 
        acknowledge_packet = IP(dst = CLIENT_IP, src = SERVER_IP)/UDP(sport = ascii,dport = 24601)
        send(acknowledge_packet)
        if ascii == 4:
            break

        message.append((chr(ascii), index))

    message.sort(key = lambda x: x[1])
    message = list(set(message))
    missing = find_missing_packets(message)

    message = ''.join(['~' if i in missing else char[0] for i, char in enumerate(message)])

if __name__ == "__main__":
    main()
