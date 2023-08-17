import os
import sys
import time
import scapy.all as scapy
from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import ARP
import re
from datetime import datetime
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
# Directory to store logs
LOG_DIRECTORY = "Muninn"

# Excluded hosts file and format instructions
EXCLUDED_HOSTS_FILE = "excluded_hosts.txt"
EXCLUDED_HOSTS_FORMAT_INSTRUCTIONS = """
# Excluded Hosts Format Instructions:
# Each line should contain an IP address to be excluded from the scan.
# Example:
# 192.168.1.10
# 192.168.1.20
"""

# New hosts log file
NEW_HOSTS_LOG_FILE = "new_hosts.txt"

SKETCHY_FILE = os.path.join("Muninn", "sketchy.txt")

# Dictionary to keep track of hosts that conducted scans or attempted SSH/ping
hosts_log = {}

def create_directory_if_not_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def read_excluded_hosts(file_path):
    excluded_hosts = set()
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            for line in file:
                excluded_hosts.add(line.strip())
    return excluded_hosts

def write_excluded_hosts(file_path, excluded_hosts):
    with open(file_path, "w") as file:
        file.write(EXCLUDED_HOSTS_FORMAT_INSTRUCTIONS)
        file.write("\n".join(excluded_hosts))

def log_host(host, is_excluded=False):
    if host not in hosts_log:
        hosts_log[host] = 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - Host detected: {host}\n"
        with open(os.path.join(LOG_DIRECTORY, NEW_HOSTS_LOG_FILE), "a") as file:
            file.write(log_message)
        print(f"[*] {'Excluded ' if is_excluded else ''}Host detected: {host}")
    else:
        hosts_log[host] += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - Host {host} detected again (Total {hosts_log[host]} times)\n"
        with open(os.path.join(LOG_DIRECTORY, NEW_HOSTS_LOG_FILE), "a") as file:
            file.write(log_message)
        print(f"[*] {'Excluded ' if is_excluded else ''}Host {host} detected again (Total {hosts_log[host]} times)")



# Define the function to get the user's IP address
def get_user_ip():
    while True:
        user_ip = input("Please enter your IP address (IPv4): ")
        # Validate the input as a valid IPv4 address using a regular expression
        if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_ip):
            return user_ip
        else:
            print("Invalid IP address format. Please enter a valid IPv4 address.")

def get_current_hosts(target):
    # ARP scan to discover hosts on the network
    arp_request = ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    current_hosts = set()
    for element in answered_list:
        host_ip = element[1].psrc
        current_hosts.add(host_ip)

    return current_hosts


def scan_network(target, excluded_hosts, new_hosts_set):
    # ARP scan to discover hosts on the network
    arp_request = ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        host_ip = element[1].psrc
        if host_ip not in excluded_hosts and host_ip not in new_hosts_set:
            new_hosts_set.add(host_ip)
            log_host(host_ip)

sketchy_hosts = set()

# Function to log sketchy hosts
def log_sketchy_host(host):
    sketchy_hosts.add(host)
    with open(SKETCHY_FILE, "a") as file:
        file.write(f"Sketchy Host: {host}\n")

# Dictionary to keep track of hosts and their ping counts
ping_counts = {}


def print_summary():
    print("[*] Summary: Hosts and their ping counts")
    for host, count in ping_counts.items():
        print(f"Host: {host}, Pings: {count}")
    ping_counts.clear()  # Clear the dictionary for the next batch
    #print("[*] Debug: Contents of ping_counts after clearing:")
    #print(ping_counts)

# Dictionary to keep track of initial alerts and their counts
initial_alerts_count = {}

# Dictionary to keep track of event messages and their counts
event_alerts_count = {}

# Function to handle packet callbacks
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = None
        dst_port = None
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check for TCP layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # Log sketchy hosts
        if (ICMP in packet) or (src_port == 22) or packet.haslayer(scapy.ARP):
            # Check if source or destination IP is in the excluded hosts list
            is_src_excluded = src_ip in excluded_hosts
            is_dst_excluded = dst_ip in excluded_hosts

            if is_src_excluded or is_dst_excluded:
                if ICMP in packet:
                    log_host(src_ip, is_excluded=True)
                    event_alerts_count[(src_ip, "ICMP")] = event_alerts_count.get((src_ip, "ICMP"), 0) + 1

                # Log SSH (port 22) connection attempts
                if src_port == 22:
                    log_host(src_ip, is_excluded=True)
                    event_alerts_count[(src_ip, "SSH")] = event_alerts_count.get((src_ip, "SSH"), 0) + 1
                elif dst_port == 22:
                    log_host(dst_ip, is_excluded=True)
                    event_alerts_count[(dst_ip, "SSH")] = event_alerts_count.get((dst_ip, "SSH"), 0) + 1

                # Log ARP scan activity
                if packet.haslayer(scapy.ARP):
                    log_host(src_ip, is_excluded=True)
                    event_alerts_count[(src_ip, "ARP")] = event_alerts_count.get((src_ip, "ARP"), 0) + 1

        # Log regular activity
        if ICMP in packet:
            if src_ip not in initial_alerts_count:
                print("Look alive my Guy or Gal! " + src_ip + " Just pinged " + dst_ip + " @ " + timestamp)
                initial_alerts_count[src_ip] = 1
            else:
                log_host(src_ip)
        elif src_port == 22:
            if src_ip not in initial_alerts_count:
                print("[*] Host " + src_ip + " attempted SSH to " + dst_ip +  " @ " + timestamp)
                initial_alerts_count[src_ip] = 1
            else:
                log_host(src_ip)
        elif packet.haslayer(scapy.ARP):
            if src_ip not in initial_alerts_count:
                print("[*] Host " + src_ip + " performed ARP scan " + " @ " + timestamp)
                initial_alerts_count[src_ip] = 1
            else:
                log_host(src_ip)



# Main ********************************************************

# Print the total count of specific events
for (ip, event_type), count in event_alerts_count.items():
    print(f"Total {event_type} events for {ip}: {count}")




# Create the log directory
create_directory_if_not_exists(LOG_DIRECTORY)

# Read excluded hosts
excluded_hosts = read_excluded_hosts(os.path.join(LOG_DIRECTORY, EXCLUDED_HOSTS_FILE))

## ...

# Ask the user for the initial target IP range to scan
target = input("Enter the initial IP range to scan (e.g., 192.168.1.1/24): ")

user_ip = get_user_ip()
excluded_hosts = read_excluded_hosts(os.path.join(LOG_DIRECTORY, EXCLUDED_HOSTS_FILE))
# Get the current hosts on the network (already excluding hosts)
current_hosts = get_current_hosts(target)
excluded_hosts.update(current_hosts)
excluded_hosts.add(user_ip)
new_hosts_set = set()

# Write updated excluded hosts (including the newly discovered ones) back to the file
write_excluded_hosts(os.path.join(LOG_DIRECTORY, EXCLUDED_HOSTS_FILE), excluded_hosts)

while True:
   # timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Print a message that we're starting a new scan with the updated target
    print(f"[+] Time to hunt! Starting network scan for : {target}...")

    # Call the scan_network function with the updated target and the newly excluded hosts
    scan_network(target, excluded_hosts, new_hosts_set)

    # Capture packets for a reasonable interval
    scan_interval = 60  # Adjust the interval as needed (seconds)
    print(f"[+] {timestamp} | Listening for network activity for {scan_interval} seconds (type 'exit' and press Enter to stop)...")
    start_time = time.time()
    while True: #time.time() - start_time < scan_interval:
        scapy.sniff(prn=packet_callback, filter="ip or icmp or tcp", store=0, stop_filter=lambda x: x[scapy.IP].src == "exit")
       
        # Print Summary of scan information
        #print_summary()
        # Ask the user if they want to change the target or exit
        user_input = input("Do you want to change the target IP range or exit? (type 'exit' to exit): ")
        if user_input.lower() == "exit":
            break
        else:
            target = user_input

        # Get the current hosts on the network (already excluding hosts)
        current_hosts = get_current_hosts(target)
        excluded_hosts.update(current_hosts)

        # Write updated excluded hosts (including the newly discovered ones) back to the file
        write_excluded_hosts(os.path.join(LOG_DIRECTORY, EXCLUDED_HOSTS_FILE), excluded_hosts)

    # Display the final hosts log
    print("\n[+] Hosts Log:")
    for host, count in hosts_log.items():
        print(f"Host: {host}, Activity Count: {count}")
        print_summary()
