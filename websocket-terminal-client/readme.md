# WebSocket Terminal Client

A simple interactive Python client for connecting to terminal-style WebSocket endpoints.

## Features

- Interactive command input
- Background thread for receiving server output
- Custom Host and Origin headers
- Optional TLS certificate verification bypass (useful for lab environments)

## Requirements

- Python 3.9+
- websocket-client

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Edit the connection settings in `ws_terminal.py`:

```python
host = "example.com"
ws_url = "wss://example.com/terminal/ws"
```

Run:

```bash
python ws_terminal.py
```

Type commands and press Enter. Type `exit` to close the connection.

## Disclaimer

This project is intended for authorized testing, development, and educational use only. Ensure you have permission before connecting to systems you do not own or administer.
