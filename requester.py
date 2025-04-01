import logging
import requests
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp, sniff, show_interfaces, get_if_addr, get_if_hwaddr
import random
import threading
import time
import argparse
import configparser
import uuid
import csv
import string
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBException

# Set logging level for smbprotocol to WARNING to suppress detailed INFO messages
logging.getLogger("smbprotocol").setLevel(logging.WARNING)

# Read configuration from properties file
config = configparser.ConfigParser()
config.read('config.properties')
WEBHOOK_URL = config.get('DEFAULT', 'WEBHOOK_URL')
WINDOWS_INTERFACE = config.get('DEFAULT', 'INTERFACE')

LOGGING_LEVEL = config.get('DEFAULT', 'LOGGING_LEVEL', fallback='DEBUG').upper()
logging.basicConfig(
    level=getattr(logging, LOGGING_LEVEL, logging.DEBUG),  # Default to DEBUG if invalid level
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.info(r"""
______                          _            
| ___ \                        | |           
| |_/ /___  __ _ _   _  ___ ___| |_ ___ _ __ 
|    // _ \/ _` | | | |/ _ / __| __/ _ | '__|
| |\ |  __| (_| | |_| |  __\__ | ||  __| |   
\_| \_\___|\__, |\__,_|\___|___/\__\___|_|   
              | |                            
              |_|                            
              """)

# Only print available interfaces if debugging enabled
if logging.getLogger().isEnabledFor(logging.DEBUG):
    print("Available Interfaces on Windows:")
    show_interfaces()

# Get source IP and MAC for this interface
source_ip = get_if_addr(WINDOWS_INTERFACE)
source_mac = get_if_hwaddr(WINDOWS_INTERFACE)
print(f"Using interface '{WINDOWS_INTERFACE}' with IP {source_ip} and MAC {source_mac}")

# LLMNR and mDNS constants
LLMNR_IP = "224.0.0.252"
LLMNR_PORT = 5355
MDNS_IP = "224.0.0.251"
MDNS_PORT = 5353

# Global variables
fake_hostname = ""
flooding = False

# Read names from CSV file
first_names = []
last_names = []
with open('names.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        first_names.append(row[0])
        last_names.append(row[1])

# Read hostnames from CSV file
hostnames = []
with open('resources.csv', newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        hostnames.append(row[0])

logging.debug(f"Hostnames loaded: {hostnames}")

# Utility functions
def generate_fake_hostname():
    return random.choice(hostnames)

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

# LLMNR functions
def send_fake_llmnr_request():
    global fake_hostname
    fake_hostname = generate_fake_hostname()
    dns_query = DNSQR(qname=fake_hostname, qtype="A", qclass="IN")
    packet = (
        Ether(src=source_mac) /
        IP(src=source_ip, dst=LLMNR_IP, ttl=1) /
        UDP(sport=LLMNR_PORT, dport=LLMNR_PORT) /
        DNS(rd=0, qd=dns_query)
    )
    logging.debug(f"Sending LLMNR request for: {fake_hostname}")
    sendp(packet, iface=WINDOWS_INTERFACE, verbose=False)

def capture_llmnr_responses(poison=False, flood=False):
    logging.debug("Listening for LLMNR responses...")

    def process_packet(packet):
        summary = packet.summary()
        logging.debug("Packet captured: " + summary)
        hostname_without_local = fake_hostname.split(".")[0].lower()
        if f"llmnrresponse '{hostname_without_local}" in summary.lower():
            json_summary = '{"timestamp": "%s", "src": "%s", "dst": "%s", "message": "LLMNR response seen for %s. Responder potentially running on %s"}' % (
                packet.time, packet[IP].src, packet[IP].dst, fake_hostname, packet[IP].src)
            logging.info(f"[!] {json_summary}")
            send_webhook_alert(json_summary)
            if flood:
                global flooding
                flooding = False
                flood_responder(packet[IP].src)
            elif poison:
                send_fake_credentials(packet[IP].src)

    sniff(filter=f"udp and port {LLMNR_PORT}", iface=WINDOWS_INTERFACE, prn=process_packet, store=0)

def send_fake_llmnr_request_loop():
    try:
        while True:
            send_fake_llmnr_request()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("\nExiting LLMNR honeypot.")

# mDNS functions
def send_fake_mdns_request():
    global fake_hostname
    fake_hostname = generate_fake_hostname()
    dns_query = DNSQR(qname=fake_hostname, qtype="A", qclass="IN")
    packet = (
        Ether(src=source_mac) /
        IP(src=source_ip, dst=MDNS_IP, ttl=255) /
        UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
        DNS(rd=0, qd=dns_query)
    )
    logging.debug(f"Sending mDNS request for: {fake_hostname}")
    sendp(packet, iface=WINDOWS_INTERFACE, verbose=False)

def capture_mdns_responses(poison=False, flood=False):
    logging.debug("Listening for mDNS responses...")

    def process_packet(packet):
        summary = packet.summary()
        logging.debug("Packet captured: " + summary)
        if packet.haslayer(DNS) and packet[DNS].ancount > 0:
            for i in range(packet[DNS].ancount):
                answer = packet[DNS].an[i]
                hostname_without_local = fake_hostname.split(".")[0].lower()
                if hostname_without_local in answer.rrname.decode().lower():
                    json_summary = '{"timestamp": "%s", "src": "%s", "dst": "%s", "message": "mDNS response seen for %s. Responder potentially running on %s"}' % (
                        packet.time, packet[IP].src, packet[IP].dst, fake_hostname, packet[IP].src)
                    logging.info(f"[!] {json_summary}")
                    send_webhook_alert(json_summary)
                    if flood:
                        global flooding
                        flooding = False
                        flood_responder(packet[IP].src)
                    elif poison:
                        send_fake_credentials(packet[IP].src)
                    break

    sniff(filter=f"udp and port {MDNS_PORT}", iface=WINDOWS_INTERFACE, prn=process_packet, store=0)

def send_fake_mdns_request_loop():
    try:
        while True:
            send_fake_mdns_request()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("\nExiting mDNS honeypot.")

# SMB functions
def send_fake_credentials(target_ip):
    first_name = random.choice(first_names)
    last_name = random.choice(last_names)
    fake_username = f"{first_name.lower()}.{last_name.lower()}"
    fake_password = generate_random_password()
    logging.info(f"Sending fake credentials to {target_ip} via SMB with username: {fake_username} and password: {fake_password}")
    try:
        connection = Connection(uuid.uuid4(), target_ip, 445)
        connection.connect()
        session = Session(connection, fake_username, fake_password)
        session.connect()
        logging.info("Fake credentials sent successfully via SMB.")
    except SMBException as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            logging.debug(f"Expected access denied error while sending fake credentials via SMB: {e}")
        else:
            logging.error(f"SMBException while sending fake credentials via SMB: {e}")
    except Exception as e:
        if "No connection could be made because the target machine actively refused it" in str(e):
            logging.info(f"Responder stopped on {target_ip}. Stopping flood.")
            global flooding
            flooding = False
        else:
            logging.error(f"Exception while sending fake credentials via SMB: {e}")

def flood_responder(target_ip):
    global flooding
    flooding = True
    logging.info(f"Flooding {target_ip} with SMB authentication requests")
    while flooding:
        send_fake_credentials(target_ip)
        time.sleep(0.1)

# Webhook function
def send_webhook_alert(message: str):
    data = {
        "content": message
    }
    try:
        response = requests.post(WEBHOOK_URL, json=data)
        if response.status_code in (200, 204):
            logging.info("Webhook sent successfully.")
        else:
            logging.error(f"Failed to send webhook. Status Code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logging.error(f"Exception while sending webhook: {e}")

# Main script
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLMNR/mDNS Honeypot")
    parser.add_argument("--protocol", choices=["llmnr", "mdns", "all"], help="Protocol to use (llmnr, mdns, or all)")
    parser.add_argument("--poison", action="store_true", help="Respond to the responses with fake credentials")
    parser.add_argument("--flood", action="store_true", help="Flood the IP running Responder with SMB auth requests")
    args = parser.parse_args()

    if not args.protocol:
        parser.error("the following arguments are required: --protocol")

    if args.protocol == "llmnr" or args.protocol == "all":
        llmnr_listener_thread = threading.Thread(target=lambda: capture_llmnr_responses(poison=args.poison, flood=args.flood))
        llmnr_listener_thread.daemon = True
        llmnr_listener_thread.start()

        logging.info("Starting LLMNR honeypot...")
        llmnr_sender_thread = threading.Thread(target=lambda: send_fake_llmnr_request_loop())
        llmnr_sender_thread.daemon = True
        llmnr_sender_thread.start()

    if args.protocol == "mdns" or args.protocol == "all":
        mdns_listener_thread = threading.Thread(target=lambda: capture_mdns_responses(poison=args.poison, flood=args.flood))
        mdns_listener_thread.daemon = True
        mdns_listener_thread.start()

        logging.info("Starting mDNS honeypot...")
        mdns_sender_thread = threading.Thread(target=lambda: send_fake_mdns_request_loop())
        mdns_sender_thread.daemon = True
        mdns_sender_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("\nExiting honeypot.")
        flooding = False  # Stop flooding if the script is interrupted