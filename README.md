# Honeypot for LLMNR, mDNS, and NBT-NS

This is a project designed as a honeypot to detect the usage of tools such as Responder (https://github.com/lgandx/Responder). It periodically sends out LLMNR and mDNS requests for fake resources (taken randomly from names.csv and resources.csv), prompting tools like Responder to respond. It is setup to send JSON via a webhook.

LLMNR/mDNS is specified using the --protocol argument. 

The --poison argument can be added to the honeypot to send fake credentials generated based off the fake hostname to the host running Responder using SMB. POISON THE POISONER.

The --flood argument will stop sending requests when an IP running Responder is detected. It will then flood the IP with SMB authentication requests. This will continue until it receives an error indicating Responder is stopped. It will restart automatically if Responder is restarted.

## Requirements

- Python 3
- Scapy
- Requests

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/badc0w/Requester.git
    cd Requester
    ```

2. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

3. Change config.properties to have the webhook URL and interface. To get the proper interface name, change logging level to debug and look for the name in the table with the correct corresponding IP address.

4. ????

5. Profit

## Usage

Run the script with the desired protocol:

```sh
python requester.py --protocol llmnr (--poison) (--flood)
python requester.py --protocol mdns (--poison) (--flood)
python requester.py --protocol all (--poison) (--flood)

```

## Screenshots

- Requester Output
  
![Alt text](img/Requester-Output.png?raw=true "Requester Output")
- Responder Output
  
![Alt text](img/Responder-Output.png?raw=true "Resonder Output")
- Discord Webhook Output
  
![Alt text](img/Discord-Output.png?raw=true "Discord Webhook Output")
## TODOs

- Add NBT-NS support (couldn't get it to work)
- Get containerization to work
