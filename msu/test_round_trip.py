#!/usr/bin/env python3

"""Quick UDP round-trip test for the standalone CryptoLib processes."""

from __future__ import annotations

import socket
import sys


APPLY_IN = ("127.0.0.1", 6010)
APPLY_OUT_PORT = 8010
PROCESS_IN = ("127.0.0.1", 6012)
PROCESS_OUT_PORT = 8012
TIMEOUT_SECONDS = 3.0

from pathlib import Path

folder = Path(__file__).parent

tc_frames_path = folder / "tc_frames.txt"

TC_FRAMES_HEX = tc_frames_path.read_text().splitlines()

failed_frames = []


def bind_udp(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(TIMEOUT_SECONDS)
    return sock


def recv_packet(sock: socket.socket, label: str, frame_number: int) -> bytes:
    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        raise RuntimeError(f"timed out waiting for {label} on frame {frame_number}") from None

    print(f"  {label}: {len(data)} bytes from {addr[0]}:{addr[1]}")
    return data

def print_bytes(data: bytes, message):
    print("\n" + str(message))
    print(data.hex(sep = ' ', bytes_per_sep=1))

    for byte in data:
        char = chr(byte) if (0x20 <= byte <= 0x8E) else "."
        print(f" {char} ", flush=True, end="")

def main() -> int:
    frames = [bytes.fromhex(frame) for frame in TC_FRAMES_HEX]
    passes = 0
    fails = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx_sock:
        with bind_udp(APPLY_OUT_PORT) as apply_out, bind_udp(PROCESS_OUT_PORT) as process_out:
            for index, original in enumerate(frames, start=1):
                print(f"[{index:02d}/{len(frames)}] input {len(original)} bytes: {original.hex().upper()}")

                vcid = (original[2] & 0xFC) >> 2
                try:
                    last_applied = b""
                    for i in range(0, 10):
                        tx_sock.sendto(original, APPLY_IN)
                        applied = recv_packet(apply_out, "apply out", index)
                        last_applied = applied

                    tx_sock.sendto(last_applied, PROCESS_IN)
                    processed = recv_packet(process_out, "process out", index)
                    if processed != original:
                        print("  FAIL: final frame does not match original")
                        print(f"    original : {original.hex().upper()}")
                        print(f"    applied  : {last_applied.hex().upper()}")
                        print(f"    processed: {processed.hex().upper()}")
                        fails += 1

                    print("  OK")
                    passes += 1

                    print_bytes(original, "original")
                    print_bytes(applied, "applied")
                    print_bytes(processed, "processed")

                except Exception as e:
                    print(f"{e}")
                    fails += 1
                    failed_frames.append((index, original, vcid, e))

                print(f"  {vcid=}")


    print(f"Round-trip OK for {len(frames)} frames")
    print(f"passes: {passes}, fails: {fails}, % = {passes / (passes+fails)}")
    for index, frame, vcid, err in failed_frames:
        print(f"frame index: {index}")
        print_bytes(frame, "\t frame: ")
        print(f"\t\t vcid: {vcid}\n\t err: {err}")
    return 0



if __name__ == "__main__":
    sys.exit(main())
