#!/usr/bin/env python3
import argparse
import socket
import sys


def main():
    parser = argparse.ArgumentParser(description="TCP sender")
    parser.add_argument("--host", default="127.0.0.1", help="Receiver address")
    parser.add_argument("--port", type=int, required=True, help="Receiver port")
    src = parser.add_mutually_exclusive_group()
    src.add_argument("-m", "--message", help="Message to send")
    src.add_argument("-f", "--file", help="Path to file to send")
    args = parser.parse_args()

    if args.message is not None:
        payload = args.message.encode("utf-8")
    elif args.file:
        with open(args.file, "rb") as fh:
            payload = fh.read()
    else:
        payload = sys.stdin.buffer.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.host, args.port))
        s.sendall(payload)
        print(f"Sent {len(payload)} bytes to {args.host}:{args.port}")


if __name__ == "__main__":
    main()
