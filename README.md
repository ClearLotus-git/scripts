# backfire.htb SSRF + RCE Exploit

This Python script targets the `backfire.htb` box on Hack The Box and demonstrates a chained SSRF and RCE attack against the Havoc Teamserver exposed internally.

## Description

- Registers a fake agent with the teamserver
- Opens a socket
- Authenticates using WebSocket
- Creates a listener
- Injects an SSRF payload that results in Remote Code Execution (RCE)


##  Key Features

- AES encryption/decryption support for teamserver communication
- WebSocket handshake and payload framing
- Custom socket message formatting for Havoc communication
- SSRF + command injection payload delivery

##  Based On

- Internal mechanics of the Havoc framework
- Techniques observed during enumeration of the `backfire.htb` machine

##  Tested On

- Python 3.9+

## How to Run:
Install dependencies:

```bash
pip install -r requirements.txt
```
## Run
```
python3 backfire-exploit.py -t https://127.0.0.1:8443 -i 127.0.0.1 -p 40056
```

