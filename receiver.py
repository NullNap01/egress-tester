#!/usr/bin/env python3
import argparse
import socket


def main():
    parser = argparse.ArgumentParser(description="TCP receiver")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument("-o", "--out", help="Save each connection's payload to this path (a counter is appended for later connections)")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"Listening on {args.host}:{args.port}")

        conn_idx = 0
        while True:
            conn, addr = srv.accept()
            conn_idx += 1
            out_path = None
            out_fh = None
            if args.out:
                out_path = args.out if conn_idx == 1 else f"{args.out}.{conn_idx}"
                out_fh = open(out_path, "wb")
            with conn:
                print(f"Connection from {addr[0]}:{addr[1]}" + (f" -> {out_path}" if out_path else ""))
                total = 0
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    total += len(data)
                    if out_fh:
                        out_fh.write(data)
                    else:
                        print(data.decode("utf-8", errors="replace"), end="", flush=True)
                if out_fh:
                    out_fh.close()
                print(f"\n[{addr[0]}:{addr[1]} closed, {total} bytes"
                      + (f" saved to {out_path}" if out_path else "") + "]")


if __name__ == "__main__":
    main()
