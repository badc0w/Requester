import logging
import requests
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp, sniff, show_interfaces, get_if_addr, get_if_hwaddr
import random
import threading
import time
import argparse
import configparser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Read configuration from properties file
config = configparser.ConfigParser()
config.read('config.properties')
WEBHOOK_URL = config.get('DEFAULT', 'WEBHOOK_URL')

# List available interfaces.
print("Available Interfaces on Windows:")
show_interfaces()  
WINDOWS_INTERFACE = "Realtek Gaming 2.5GbE Family Controller"  # Change this to match the "Name" from the proper interface from above

# Get source IP and MAC for this interface.
source_ip = get_if_addr(WINDOWS_INTERFACE)
source_mac = get_if_hwaddr(WINDOWS_INTERFACE)
print(f"Using interface '{WINDOWS_INTERFACE}' with IP {source_ip} and MAC {source_mac}")

# LLMNR uses multicast IP 224.0.0.252 and UDP port 5355 with TTL=1.
LLMNR_IP = "224.0.0.252"
LLMNR_PORT = 5355

# mDNS uses multicast IP 224.0.0.251 and UDP port 5353 with TTL=255.
MDNS_IP = "224.0.0.251"
MDNS_PORT = 5353

# Global variable to store the fake hostname
fake_hostname = ""

def generate_fake_hostname():
    return f"fake{random.randint(1000, 9999)}"

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

def capture_llmnr_responses():
    logging.debug("Listening for LLMNR responses...")

    def process_packet(packet):
        summary = packet.summary()
        logging.debug("Packet captured: " + summary)
        if "llmnrresponse 'fake" in summary.lower():
            json_summary = '{"timestamp": "%s", "src": "%s", "dst": "%s", "message": "LLMNR response seen for %s. Responder potentially running on %s"}' % (packet.time, packet[IP].src, packet[IP].dst, fake_hostname, packet[IP].src)
            logging.info(f"[!] {json_summary}")
            send_webhook_alert(json_summary)

    sniff(filter=f"udp and port {LLMNR_PORT}", iface=WINDOWS_INTERFACE, prn=process_packet, store=0)

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

def capture_mdns_responses():
    logging.debug("Listening for mDNS responses...")

    def process_packet(packet):
        summary = packet.summary()
        logging.debug("Packet captured: " + summary)
        
        if packet.haslayer(DNS) and packet[DNS].ancount > 0:
            for i in range(packet[DNS].ancount):
                answer = packet[DNS].an[i]
                if "fake" in answer.rrname.decode().lower():
                    json_summary = '{"timestamp": "%s", "src": "%s", "dst": "%s", "message": "mDNS response seen for %s. Responder potentially running on %s"}' % (packet.time, packet[IP].src, packet[IP].dst, fake_hostname, packet[IP].src)
                    logging.info(f"[!] {json_summary}")
                    send_webhook_alert(json_summary)
                    break

    sniff(filter=f"udp and port {MDNS_PORT}", iface=WINDOWS_INTERFACE, prn=process_packet, store=0)

def send_fake_llmnr_request_loop():
    try:
        while True:
            send_fake_llmnr_request()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("\nExiting LLMNR honeypot.")

def send_fake_mdns_request_loop():
    try:
        while True:
            send_fake_mdns_request()
            time.sleep(5)
    except KeyboardInterrupt:
        logging.info("\nExiting mDNS honeypot.")

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLMNR/mDNS Honeypot")
    parser.add_argument("--protocol", choices=["llmnr", "mdns", "all"], required=True, help="Protocol to use (llmnr, mdns, or all)")
    args = parser.parse_args()

    if args.protocol == "llmnr" or args.protocol == "all":
        llmnr_listener_thread = threading.Thread(target=capture_llmnr_responses)
        llmnr_listener_thread.daemon = True
        llmnr_listener_thread.start()
        
        logging.info("Starting LLMNR honeypot...")
        llmnr_sender_thread = threading.Thread(target=lambda: send_fake_llmnr_request_loop())
        llmnr_sender_thread.daemon = True
        llmnr_sender_thread.start()

    if args.protocol == "mdns" or args.protocol == "all":
        mdns_listener_thread = threading.Thread(target=capture_mdns_responses)
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

