from scapy.all import *
import time
import csv

def process_packet(pkt):
    global ip_mac_map, alerted_ips, traffic_tracker, syn_tracker
    
    # --- ARP Spoofing Logic ---
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2:
            sip = pkt[ARP].psrc
            smac = pkt[ARP].hwsrc
            if sip in ip_mac_map and ip_mac_map[sip] != smac:
                print(f"!!! ALERT: ARP spoof detected from source IP: {sip} !!!")
            else:
                ip_mac_map[sip] = smac
        return

    # --- IP Packet Logic ---
    if pkt.haslayer(IP):
        src = pkt[IP].src
        
        # --- Traffic Burst Logic with DEBUG PRINT ---
        if src not in traffic_tracker:
            traffic_tracker[src] = {"byte_count": 0, "timestamp": time.time()}
        
        traffic_tracker[src]["byte_count"] += len(pkt)
        time_passed = time.time() - traffic_tracker[src]['timestamp']
        
        # DEBUG: Print the current traffic status
        print(f"[Traffic Debug] IP: {src} has sent {traffic_tracker[src]['byte_count']} bytes in {time_passed:.2f} seconds.")

        if time_passed > 2:
            if traffic_tracker[src]["byte_count"] > 4000:
                print(f"!!! ALERT: Traffic burst detected from IP address: {src} !!!")
            # Reset for the next window
            traffic_tracker[src]["timestamp"] = time.time()
            traffic_tracker[src]["byte_count"] = 0

        # --- TCP-Specific Logic ---
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            
            # --- Port Scan Logic with DEBUG PRINT ---
            if src not in ip_port_map:
                ip_port_map[src] = set()
            
            ip_port_map[src].add(dport)
            
            # DEBUG: Print the current port count for this IP
            print(f"[Port Scan Debug] IP: {src} has now scanned {len(ip_port_map[src])} unique ports.")
            
            if len(ip_port_map[src]) > 3 and src not in alerted_ips:
                print(f"!!! ALERT: Port scan detected from IP address: {src} !!!")
                alerted_ips.add(src)

            # --- SYN Flood Logic with DEBUG PRINT ---
            if pkt[TCP].flags == 'S':
                if src not in syn_tracker:
                    syn_tracker[src] = {'count': 0, 'timestamp': time.time()}
                
                syn_tracker[src]['count'] += 1
                
                # DEBUG: Print the current SYN count
                print(f"[SYN Flood Debug] IP: {src} has sent {syn_tracker[src]['count']} SYNs.")

                syn_time_passed = time.time() - syn_tracker[src]['timestamp']
                if syn_time_passed > 5:
                    if syn_tracker[src]['count'] > 4:
                        print(f"!!! ALERT: SYN flood detected from IP address: {src} !!!")
                    # Reset for the next window
                    syn_tracker[src]['timestamp'] = time.time()
                    syn_tracker[src]['count'] = 0
    

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

sniff(prn=process_packet, store=0)

# header = ['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'length', 'flags', 'rule_based_alert']

# This try...except block will run the sniffer and handle the CSV file
# try:
#     with open('network_traffic.csv', 'w', newline='') as csv_file:
#         csv_writer = csv.writer(csv_file)
#         csv_writer.writerow(header)

#         print("Sniffer starting... Press Ctrl+C to stop.")

#         # This new lambda calls process_packet, then writes the result
#         def callback_function(pkt):
#             # 1. Analyze the packet and get the row
#             row_to_write = process_packet(pkt)
            
#             # 2. Write to CSV only if a row was returned
#             if row_to_write:
#                 csv_writer.writerow(row_to_write)
#                 csv_file.flush()

#         # This is the single, correct sniff call
#         sniff(prn=callback_function, iface="Ethernet", store=0)

# except KeyboardInterrupt:
#     print("\nSniffer stopped by user. CSV file saved.")
# except Exception as e:
#     print(f"An error occurred: {e}")