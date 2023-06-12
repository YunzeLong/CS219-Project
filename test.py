import argparse
import json
import socket
import decode
import base64
import random
import send_mail
import datetime

broken_devices = set()


def examine_packet(packet: bytes) -> bool:
    # look for json start point
    start_position = packet.find(b"{")
    json_payload = packet[start_position:]

    # chain of conditions: isJson -> isJoinReq -> isLeaked
    try:
        json_payload = json.loads(json_payload.decode("utf-8"))
        if "rxpk" not in json_payload:
            return False

        for rxpk_field in json_payload["rxpk"]:
            if "data" not in rxpk_field:
                continue

            raw_data = rxpk_field["data"]
            decoded_data = base64.b64decode(raw_data)
            if not decode.filter_join_req(decoded_data):
                continue
            
            # print('[join-request]')
            
            dev_eui = decode.extract_dev_eui(decoded_data)
            if dev_eui in broken_devices:
                print(f'[known-leaked-device] {dev_eui.hex()}')
                return True

            if decode.key_collision_check(decoded_data):
                broken_devices.add(dev_eui)
                print(f'[new-leaked-device] {dev_eui.hex()}')
                return True
    except:
        return False
    finally:
        return False


if __name__ == "__main__":

    
    packet = b'\x02\x86~\x00\xaaUZ\xdc\xdb\xa8#\xbe{"rxpk":[{"jver":1,"tmst":4189133344,"chan":5,"rfch":1,"freq":904.900000,"mid": 9,"stat":1,"crc":"0x03a2","crc_calc":"0x03a2","crc_match":1,"modu":"LORA","datr":"SF10BW125","codr":"4/5","rssis":-51,"lsnr":15.2,"foff":134,"rssi":-51,"size":23,"data":"AAkAAAAAAACAAABQMiHx9yw9YyfFWg0="},{"jver":1,"tmst":4189133351,"chan":7,"rfch":1,"freq":905.300000,"mid": 8,"stat":-1,"crc":"0x0b28","crc_calc":"0x0e5c","crc_match":0,"modu":"LORA","datr":"SF10BW125","codr":"4/5","rssis":-113,"lsnr":-13.5,"foff":25133,"rssi":-101,"size":23,"data":"AAljgAQAMFoACABgUrHx9yw94CfFWlw="}]}'
    t1 = datetime.datetime.now()
    examine_packet(packet)
    t2 = datetime.datetime.now() 
    diff = t2-t1
    print(diff.microseconds)