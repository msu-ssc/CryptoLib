import socket
import json
from  pathlib import Path
from rich.pretty import  pprint
from typing import Literal


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


    data = Path("/home/alexanderm/Dev/CryptoLib/lems_a3_standalone_app/test_tc_frames.json")
    tc_frames = json.loads(data.read_text(encoding="utf-8"))


    recv_sock.bind(("0.0.0.0", 8010))
    responses:[CryptoResponse] = [] 

    while True:
        print("----")
        inp = input("Type 'q' to stop looping. Type a # to set set_vcid") 
        if inp == 'q':
            break
        
        
        #send_sock.sendto(outgoing_message, ("cryptolib", 6010))

        for frame in tc_frames:
            for i in range(0, 5):
                pprint(frame)
                outgoing_message = bytes.fromhex(frame["tc_frame"])

                send_sock.sendto(outgoing_message, ("cryptolib", 6010))
                print("sent (TC_APPLY_PORT): ")

                print_bytes(outgoing_message)


                #print("sent (TC_PROCESS_PORT): ")
                #print_bytes(outgoing_message)

                print("waiting to recieve (APPLY)")
                recv_sock.settimeout(0.25)
                data = "TIMED_OUT"
                try: 
                    data, addr = recv_sock.recvfrom(4096)
                    print("recv (TC_APPLY_PORT): ")
                    print_bytes(data)

                    response = CryptoResponse(vcid=frame["vcid"], set_vcid=int(inp), input_tcframe=frame["tc_frame"], output_tcframe=data.hex())
                    responses.append(response)
                except Exception as e: 
                    response = CryptoResponse(vcid=frame["vcid"], set_vcid=int(inp), input_tcframe=frame["tc_frame"], output_tcframe=str(e))
                    responses.append(response)

    json_string = CryptoResponse.responses_to_json(responses)

    data_dict = json.loads(json_string)

    pretty_json = json.dumps(data_dict, indent=4)


    Path("/home/alexanderm/Dev/CryptoLib/lems_a3_standalone_app/responses.json").write_text(pretty_json, encoding="utf-8")

if __name__ == "__main__":
    main()
