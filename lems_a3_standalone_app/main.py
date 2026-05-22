import socket
import json
from  pathlib import Path
from rich.pretty import  pprint
from typing import Literal
from dataclasses import dataclass

@dataclass
class CryptoResponse:
    input_tcframe: bytes
    vcid: int
    output_tcframe: bytes | Literal["TIMED_OUT"]
    set_vcid: int

    def __init__(self, input_tcframe: bytes, vcid: int, set_vcid: int, output_tcframe: bytes): 
        self.input_tcframe = input_tcframe
        self.vcid = vcid
        self.set_vcid = set_vcid
        self.output_tcframe = output_tcframe
    
    def to_json(self) -> str:
        # Check type to avoid AttributeError if output_tcframe is "TIMED_OUT"
        out_frame = (
            self.output_tcframe.hex() 
            if isinstance(self.output_tcframe, bytes) 
            else self.output_tcframe
        )
        
        # Create a dictionary and dump to JSON for proper character escaping
        pprint((self.input_tcframe, type(self.input_tcframe)))
        data = {
            "input_tcframe":  self.input_tcframe,
            "vcid": self.vcid,
            "output_tcframe": out_frame,
            "set_vcid": self.set_vcid
        }
        
        return json.dumps(data)
    def responses_to_json(responses: ["CryptoResponse"]) -> str: 
        output_json = "["
        for index,resp in enumerate(responses):
            resp_json = resp.to_json()
            if index != len(responses) - 1:
                output_json += f"{resp_json},"
                continue
            output_json += f"{resp_json}"
        output_json += "]"
        return output_json
        
def print_bytes(data: bytes) -> None:
    print(f" {data.hex(sep=' ')}")
    print("".join("  " + (chr(x) if (0x20 <= x <= 0x7E) else ".") for x in data))
    print(f"len of data: {len(data)}")


def main():
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    data = Path("/home/alexandermeade/Desktop/CryptoLib/lems_a3_standalone_app/test_tc_frames.json")


    recv_sock.bind(("0.0.0.0", 8010))
    responses:[CryptoResponse] = [] 

    # process_recv_sock.bind(("0.0.0.0", 8011))

    tcframe = "20 77 00 4e 00 18 b3 c0 00 00 31 0a 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 50 41 52 41 4d 45 54 45 52 00 00 00 00 00 00 50 4c 41 49 4e 2d 54 45 58 54 2d 41 53 43 49 49 2d 56 41 4c 55 45 00 00 00 00 00 00 00 00 00 00 73 f8"
    outgoing_message = bytes.fromhex(tcframe)
    vcid = input("Set vcid: ")
    send_sock.sendto(outgoing_message, ("cryptolib", 6010))
    while True:
        print("sent (TC_APPLY_PORT): ")

        print_bytes(outgoing_message)

        print("waiting to recieve (APPLY)")
        # 2 second timeout
        recv_sock.settimeout(2.0)
        data = "TIMED_OUT"
        
        try: 
            data, addr = recv_sock.recvfrom(4096)
            print("recv (TC_APPLY_PORT): ")
            print_bytes(data)
            response = CryptoResponse(vcid=vcid, set_vcid=vcid, input_tcframe=tcframe, output_tcframe=data.hex())
            pprint(response)

        except Exception as e: 
            response = CryptoResponse(vcid=vcid, set_vcid=vcid,input_tcframe= tcframe, output_tcframe=str(e))
            pprint(response)

if __name__ == "__main__":
    main()
