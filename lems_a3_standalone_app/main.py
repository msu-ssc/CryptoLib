import socket

# 2077006200C000010000000000000000000000002077004E0018B3C00000310A00504C41494E2D544558542D41534349492D504152414D45544552000000000000504C41494E2D544558542D41534349492D56414C55450000000000000000000073F8


def print_bytes(data: bytes) -> None:
    print(f" {data.hex(sep=' ')}")
    print("".join("  " + (chr(x) if (0x20 <= x <= 0x7E) else ".") for x in data))
    print(f"len of data: {len(data)}")


def main():
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    process_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    process_recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    recv_sock.bind(("0.0.0.0", 8010))
    # process_recv_sock.bind(("0.0.0.0", 8011))

    # tcframe = "20 77 00 4e 00 18 b3 c0 00 00 31 0a 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 50 41 52 41 4d 45 54 45 52 00 00 00 00 00 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 56 41 4c 55 45 00 00 00 00 00 00 00 00 00 00 73 f8"
    tcframe = "18 b3 c0 00 00 31 0a 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 50 41 52 41 4d 45 54 45 52 00 00 00 00 00 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 56 41 4c 55 45 00 00 00 00 00 00 00 00 00 00"
    outgoing_message = bytes.fromhex(tcframe)

    send_sock.sendto(outgoing_message, ("cryptolib", 6010))

    print("sent (TC_APPLY_PORT): ")
    print_bytes(outgoing_message)

    print("sent (TC_PROCESS_PORT): ")
    print_bytes(outgoing_message)

    while True:
        print("waiting to recieve (APPLY)")
        data, addr = recv_sock.recvfrom(4096)

        print("recv (TC_APPLY_PORT): ")
        print_bytes(data)

        print("waiting to recieve (PROCESS)")
        process_send_sock.sendto(data, ("cryptolib", 6012))
        process_data, addr2 = process_recv_sock.recvfrom(4096)

        print("recv (TC_PROCESS_PORT): ")
        print_bytes(process_data)
        # print(f"data is same is outgoing message: {data == outgoing_message}")


if __name__ == "__main__":
    main()
