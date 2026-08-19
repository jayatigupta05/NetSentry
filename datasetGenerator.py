from scapy.all import *
import time
import csv

def process_packet(pkt):
    """
    Analyzes a packet and returns a row to be logged.
    Returns:
        A list (row) if the packet is to be logged, otherwise None.
    """
    # This line is essential for updating the trackers
    global ip_mac_map, alerted_ips, traffic_tracker, syn_tracker
    
    is_alert = 0
    timestamp = time.time()

    # --- ARP Spoofing Logic ---
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2: # is-at (a reply)
            sip = pkt[ARP].psrc
            smac = pkt[ARP].hwsrc
            dip = pkt[ARP].pdst
            
            if sip in ip_mac_map and ip_mac_map[sip] != smac:
                print(f"!!! ALERT: ARP spoof detected from source IP: {sip} !!!")
                is_alert = 1
            else:
                ip_mac_map[sip] = smac
            
            # Return the row to be logged
            row = [timestamp, sip, dip, -1, -1, 'ARP', len(pkt), '', is_alert]
            return row
        
        # If it's an ARP packet but not a reply, we ignore it
        return None

    # --- IP Packet Logic ---
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        protocol = pkt[IP].proto
        pkt_len = len(pkt)
        
        # Initialize defaults
        sport, dport = -1, -1
        flags = ''

        # --- Traffic Burst Logic ---
        if src not in traffic_tracker:
            traffic_tracker[src] = {"byte_count": 0, "timestamp": time.time()}
        
        traffic_tracker[src]["byte_count"] += pkt_len
        time_passed = time.time() - traffic_tracker[src]['timestamp']

        if time_passed > 2:
            # Using lowered threshold for testing
            if traffic_tracker[src]["byte_count"] > 4000: 
                print(f"!!! ALERT: Traffic burst detected from IP address: {src} !!!")
                is_alert = 1
            traffic_tracker[src]["timestamp"] = time.time()
            traffic_tracker[src]["byte_count"] = 0

        # --- TCP-Specific Logic ---
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            
            # --- Port Scan Logic ---
            if src not in ip_port_map:
                ip_port_map[src] = set()
            
            ip_port_map[src].add(dport)
            
            if len(ip_port_map[src]) > 3 and src not in alerted_ips: # Lowered threshold
                print(f"!!! ALERT: Port scan detected from IP address: {src} !!!")
                is_alert = 1
                alerted_ips.add(src)

            # --- SYN Flood Logic ---
            if 'S' in flags: # Check if SYN flag is present
                if src not in syn_tracker:
                    syn_tracker[src] = {'count': 0, 'timestamp': time.time()}
                
                syn_tracker[src]['count'] += 1
                syn_time_passed = time.time() - syn_tracker[src]['timestamp']
                
                if syn_time_passed > 5:
                    if syn_tracker[src]['count'] > 4: # Lowered threshold
                        print(f"!!! ALERT: SYN flood detected from IP address: {src} !!!")
                        is_alert = 1
                    syn_tracker[src]['timestamp'] = time.time()
                    syn_tracker[src]['count'] = 0
        
        # Return the row for the IP packet
        row = [timestamp, src, dst, sport, dport, protocol, pkt_len, flags, is_alert]
        return row

    # If it's not ARP or IP, we ignore it
    return None

# --- Main Script Execution ---

print('Initializing trackers...')

# For port scan detector
ip_port_map = dict()
alerted_ips = set()

# For Traffic Burst detector
traffic_tracker = dict()

# For ARP spoof detector
ip_mac_map = dict()

# For TCP SYN flood detector
syn_tracker = dict()

# CSV Header
header = ['timestamp', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol', 'length', 'flags', 'rule_based_alert']

try:
    with open('network_traffic.csv', 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(header)

        print("Sniffer starting... Press Ctrl+C to stop.")

        # This new lambda calls process_packet, then writes the result
        def callback_function(pkt):
            # 1. Analyze the packet and get the row
            row_to_write = process_packet(pkt)
            
            # 2. Write to CSV only if a row was returned
            if row_to_write:
                csv_writer.writerow(row_to_write)
                csv_file.flush()

        # This is the single, correct sniff call with the interface specified
        sniff(prn=callback_function, iface="Ethernet", store=0)

except KeyboardInterrupt:
    print("\nSniffer stopped by user. CSV file saved.")
except Exception as e:
    print(f"An error occurred: {e}")