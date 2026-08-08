#!/usr/bin/env python3
"""Bounded Phase 17 namespace probes. Successful runs print no payload data."""

import argparse
import socket
import struct


def endpoint(family, address, port):
    return (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)


def tcp(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        sock.connect(endpoint(family, address, 18080))
        sock.sendall(b"phase17")
        if sock.recv(8) != b"ok":
            raise RuntimeError("tcp witness rejected")


def udp(family, address):
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(b"phase17", endpoint(family, address, 18081))
        if sock.recvfrom(8)[0] != b"ok":
            raise RuntimeError("udp witness rejected")


def dns(family, address):
    query = struct.pack("!HHHHHH", 0x1701, 0x0100, 1, 0, 0, 0) + b"\x07invalid\x00\x00\x01\x00\x01"
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(query, endpoint(family, address, 1053))
        response = sock.recvfrom(512)[0]
        if len(response) < 12 or response[:2] != query[:2] or response[2:4] != b"\x81\x83":
            raise RuntimeError("dns witness rejected")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=("4", "6"), required=True)
    parser.add_argument("--kind", choices=("tcp", "udp", "dns", "all"), required=True)
    args = parser.parse_args()
    family = socket.AF_INET if args.family == "4" else socket.AF_INET6
    address = "198.51.100.2" if args.family == "4" else "2001:db8:201::2"
    probes = (tcp, udp, dns) if args.kind == "all" else ({"tcp": tcp, "udp": udp, "dns": dns}[args.kind],)
    for probe in probes:
        probe(family, address)


if __name__ == "__main__":
    main()
