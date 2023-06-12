from Crypto.Cipher import AES
from Crypto.Hash import CMAC
import base64

broken_keys: list[bytes] = [
    b'\xca\x1b\xdb\x9b\x2c\x20\x19\xf6\x32\xeb\x97\x74\xe5\x56\x11\x62'
]

def calculate_cmac_digest(key: bytes, payload: bytes) -> bytes:
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(payload)
    digest = cobj.digest()
    return digest


def calculate_mic_digest(key: bytes, payload: bytes) -> bytes:
    digest = calculate_cmac_digest(key, payload)
    mic = digest[0:4]
    return mic


def get_all_broken_mics(payload: bytes) -> list[bytes]:
    mics: list[bytes] = []
    for key in broken_keys:
        mics.append(calculate_mic_digest(key, payload))
    return mics


def key_collision_check(packet: bytes) -> bool:
    length = len(packet)
    payload = packet[0 : length - 4]
    mic = extract_mic(packet)
    broken_mics = get_all_broken_mics(payload)
    for broken_mic in broken_mics:
        if mic == broken_mic:
            return True
    return False


def filter_join_req(packet: bytes) -> bool:
    header = packet[0]
    if header & 0b11100000 == 0:
        return True
    return False


def load_keys(keys: list[bytes]):
    broken_keys = keys


def extract_mic(packet: bytes):
    length = len(packet)
    return packet[length - 4 : length]


def extract_join_request(packet: bytes):
    if len(packet) != 23:
        raise ValueError("packet does not contain join request")
    return packet[1:19]


def extract_join_eui(packet: bytes):
    join_req = extract_join_request(packet)
    return join_req[0:8]


def extract_dev_eui(packet: bytes):
    join_req = extract_join_request(packet)
    return join_req[8:16]


if __name__ == "__main__":
    sample = "AAkAAAAAAACAAABQMiHx9yw9YyfFWg0="
    sample_decoded = base64.b64decode(sample)
    print(sample_decoded.hex())
    print(len(sample_decoded))
    print(filter_join_req(sample_decoded))
    print(extract_join_eui(sample_decoded).hex())
    print(extract_dev_eui(sample_decoded).hex())

    payload = sample_decoded[0:20]
    key = broken_keys[0]
    print(key.hex())
    print('cmac: ' + calculate_cmac_digest(key, payload).hex())
    print("mic: " + calculate_mic_digest(key, payload).hex())
    print('mic_orig: ' + extract_mic(sample_decoded).hex())