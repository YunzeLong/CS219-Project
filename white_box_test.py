import time
from socket_forwarder import *
import decode

packet = b'\x02\x9d}\x00\xaaUZ\xdc\xdb\xa8#\xbe{"rxpk":[{"jver":1,"tmst":4069131864,"chan":3,"rfch":0,"freq":904.500000,"mid":10,"stat":-1,"crc":"0x0b28","crc_calc":"0x04ec","crc_match":0,"modu":"LORA","datr":"SF10BW125","codr":"4/5","rssis":-113,"lsnr":-13.2,"foff":-24881,"rssi":-101,"size":23,"data":"wAkAxQgAAGMWEABQUuHx9yw94CfFWl0="},{"jver":1,"tmst":4069131887,"chan":5,"rfch":1,"freq":904.900000,"mid": 8,"stat":1,"crc":"0x03a2","crc_calc":"0x03a2","crc_match":1,"modu":"LORA","datr":"SF10BW125","codr":"4/5","rssis":-51,"lsnr":15.0,"foff":117,"rssi":-51,"size":23,"data":"AAkAAAAAAACAAABQMiHx9yw9YyfFWg0="},{"jver":1,"tmst":4069131902,"chan":7,"rfch":1,"freq":905.300000,"mid": 9,"stat":-1,"crc":"0x034e","crc_calc":"0x9909","crc_match":0,"modu":"LORA","datr":"SF10BW125","codr":"4/5","rssis":-112,"lsnr":-12.0,"foff":25238,"rssi":-101,"size":23,"data":"AAEzAIQAADMsCABQMT319zw9byPFygo="}]}'

OUT_FILE = "stress_test.result.csv"

def non_logger(data: str):
    pass

def run_test(count: int) -> float:
    start = time.time()

    for i in range(1, count):
        examine_packet(packet, non_logger)

    end = time.time()
    return end - start

outfile = open(OUT_FILE, 'w')

outfile.write('Packet Count, Processing Time\n')
for i in range(1, 1000):
    outfile.write(f'{i}, {run_test(i)}\n')
outfile.close()

print('done')
