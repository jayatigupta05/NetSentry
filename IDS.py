from scapy.all import *
import time

def process_packet(pkt):
    """
    Invoked everytime a packet is detected
    Args:
        pkt: detected packet
    """
    global ip_mac_map, alerted_ips, traffic_tracker, syn_tracker
    if pkt.haslayer(ARP):   # type: ignore
        # ARP SPOOF DETECTOR
        if pkt[ARP].op == 2:
            sip = pkt[ARP].psrc
            smac = pkt[ARP].hwsrc
            if sip not in ip_mac_map:
                ip_mac_map[sip] = smac
            else:
                if smac != ip_mac_map[sip]:
                    print(f"ALERT: ARP spoof detected from source IP: {sip}")
    
    if pkt.haslayer(IP):
        sport, dport = None, None
        src = pkt[IP].src
        dst = pkt[IP].dst

        # TRAFFIC BURST DETECTOR
        pkt_len = len(pkt)
        print(f"IP Packet: {src} -> {dst}")
        if src in traffic_tracker:
            traffic_tracker[src]["byte_count"] += pkt_len
            curr_time = time.time()
            time_passed = curr_time - traffic_tracker[src]["timestamp"]
            if time_passed >= 2:
                if traffic_tracker[src]["byte_count"] >= 4000:
                    print(f"ALERT: Traffic burst detected from IP address: {src}")
                traffic_tracker[src]["timestamp"] = curr_time
                traffic_tracker[src]["byte_count"] = 0
        else:
            traffic_tracker[src] = {"byte_count": pkt_len,
                                    "timestamp" : time.time()}

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            print(f"TCP/IP Packet: src: {src} | dst: {dst} | sport: {sport} | dport: {dport}")

            # PORT SCAN DETECTOR
            if src in ip_port_map:
                ip_port_map[src].add(dport)
            else:
                ip_port_map[src] = {dport}

            if len(ip_port_map[src]) > 3 and src not in alerted_ips:
                print(f"ALERT: Port scan detected from IP address: {src}")
                alerted_ips.add(src)

            # TCP SYN FLOOD DETECTOR
            if pkt[TCP].flags == 'S':
                if src not in syn_tracker:
                    syn_tracker[src] = {'count': 0, 'timestamp': time.time()}
                syn_tracker[src]["count"] += 1

                passed_time = time.time() - syn_tracker[src]['timestamp']
                if passed_time >= 5:
                    if syn_tracker[src]['count'] >= 4:
                        print(f"ALERT: SYN flood detected from IP address: {src}")
                    syn_tracker[src]['count'] = 0
                    syn_tracker[src]['timestamp'] = time.time()

    

print('Starting sniffer')

# For port scan detector
ip_port_map = dict()    # {src: [dst]}
alerted_ips = set()

# For Traffic Burst detector
traffic_tracker = dict()    # {src: {'byte_count': X, 'timestamp': Y}}

# For ARP spoof detector
ip_mac_map = dict()

# For TCP SYN flood detector
syn_tracker = dict()    # {'ip': {'count': X, 'timestamp': Y}}

sniff(prn=process_packet, iface="Ethernet", store=0)