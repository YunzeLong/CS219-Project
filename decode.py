from Crypto.Cipher import AES
from Crypto.Hash import CMAC

broken_keys: list[bytes]


def get_mic(key: bytes, payload: bytes) -> bytes:
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(payload)
    digest = cobj.digest()
    mic = digest[0:4]
    return mic


def get_all_mic(payload: bytes) -> list[bytes]:
    mics: list[bytes] = []
    for key in broken_keys:
        mics.append(get_mic(key, payload))
    return mics


def key_collision_check(packet: bytes) -> bool:
    length = len(packet)
    payload = packet[4:length]
    mic = packet[0:3]
    broken_mics = get_all_mic(payload)
    for broken_mic in broken_mics:
        if mic == broken_mic:
            return True
    return False
