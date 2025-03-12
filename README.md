# Honeypot for LLMNR, mDNS, and NBT-NS

This is a project designed as a honeypot to detect the usage of tools such as Responder (https://github.com/lgandx/Responder). It periodically sends out LLMNR and mDNS requests for fake resources, prompting tools like Responder to respond. It is setup to send JSON via a webhook

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

3. Change config.properties to have the webhook URL.

4. ????

5. Profit

## Usage

Run the script with the desired protocol:

```sh
python requester.py --protocol llmnr
python requester.py --protocol mdns
python requester.py --protocol all
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