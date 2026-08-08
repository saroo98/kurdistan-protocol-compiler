#!/usr/bin/env python3
"""Private namespace witness for Phase 17. It emits no request data."""

import argparse
import selectors
import signal
import socket


def listener(family, kind, address, port):
    sock = socket.socket(family, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((address, port))
    if kind == socket.SOCK_STREAM:
        sock.listen(16)
    sock.setblocking(False)
    return sock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", required=True)
    args = parser.parse_args()
    selector = selectors.DefaultSelector()
    sockets = []
    for family, address in ((socket.AF_INET, "198.51.100.2"), (socket.AF_INET6, "2001:db8:201::2")):
        for kind, port in ((socket.SOCK_STREAM, 18080), (socket.SOCK_DGRAM, 18081), (socket.SOCK_DGRAM, 1053)):
            sock = listener(family, kind, address, port)
            selector.register(sock, selectors.EVENT_READ, (kind, port))
            sockets.append(sock)
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with open(args.ready, "x", encoding="ascii") as ready:
        ready.write("ready\n")
    try:
        while running:
            for key, _ in selector.select(timeout=0.2):
                sock = key.fileobj
                kind, port = key.data
                if kind == socket.SOCK_STREAM:
                    conn, _ = sock.accept()
                    with conn:
                        conn.settimeout(1)
                        data = conn.recv(32)
                        if data == b"phase17":
                            conn.sendall(b"ok")
                else:
                    data, peer = sock.recvfrom(512)
                    if port == 1053:
                        if len(data) >= 12:
                            response = data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:]
                            sock.sendto(response, peer)
                    elif data == b"phase17":
                        sock.sendto(b"ok", peer)
    finally:
        for sock in sockets:
            selector.unregister(sock)
            sock.close()


if __name__ == "__main__":
    main()
