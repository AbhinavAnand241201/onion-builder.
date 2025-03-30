#!/usr/bin/env python3
import json
import sys
import os
import binascii
import hashlib
import hmac
from io import BytesIO
from typing import List, Dict, Any, Tuple

from Cryptodome.Cipher import ChaCha20
from electrum_ecc import ECPrivkey, ECPubkey

ROUTING_INFO_SIZE = 1300
HOP_DATA_SIZE = 65
NUM_STREAM_BYTES = ROUTING_INFO_SIZE + HOP_DATA_SIZE
HMAC_SIZE = 32

def hex_to_bytes(hex_string: str) -> bytes:
    return binascii.unhexlify(hex_string)

def bytes_to_hex(byte_data: bytes) -> str:
    return binascii.hexlify(byte_data).decode('ascii')

def generate_key(key_type: str, shared_secret: bytes) -> bytes:
    h = hmac.new(key_type.encode(), shared_secret, hashlib.sha256)
    return h.digest()

def generate_cipher_stream(key: bytes, length: int) -> bytes:
    nonce = bytes([0] * 12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(bytes([0] * length))

def right_shift(array: bytearray, amount: int) -> None:
    array_len = len(array)
    temp = array.copy()
    for i in range(amount):
        array[i] = 0
    for i in range(amount, array_len):
        array[i] = temp[i - amount]

def xor(dest: bytearray, a: bytes, b: bytes) -> None:
    for i in range(min(len(a), len(b), len(dest))):
        dest[i] = a[i] ^ b[i]

def calc_mac(key: bytes, data: bytes) -> bytes:
    h = hmac.new(key, data, hashlib.sha256)
    return h.digest()

def scalar_mult(pubkey: ECPubkey, scalar: int) -> ECPubkey:
    priv = ECPrivkey.from_int(scalar)
    return pubkey.mul(priv.secret)

def generate_header_padding(key_type: str, num_hops: int, hop_size: int, shared_secrets: List[bytes]) -> bytes:
    padding = bytearray(ROUTING_INFO_SIZE)
    for i in range(num_hops - 1):
        rho_key = generate_key(key_type, shared_secrets[i])
        stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
        for j in range(hop_size, ROUTING_INFO_SIZE):
            padding[j] ^= stream_bytes[j]
    return bytes(padding[hop_size:])

def create_onion_packet(
    payment_path: List[ECPubkey], 
    session_key: ECPrivkey, 
    hops_data: List[bytes], 
    assoc_data: bytes
) -> bytes:
    num_hops = len(payment_path)
    hop_shared_secrets = []
    ephemeral_key = session_key.secret
    for i in range(num_hops):
        ecdh_result = scalar_mult(payment_path[i], ephemeral_key)
        shared_secret = hashlib.sha256(ecdh_result.get_public_key_bytes()).digest()
        hop_shared_secrets.append(shared_secret)
        ephemeral_priv_key = ECPrivkey.from_int(ephemeral_key)
        ephemeral_pub_key = ephemeral_priv_key.get_public_key()
        blinding_factor_preimage = ephemeral_pub_key.get_public_key_bytes() + shared_secret
        blinding_factor = int.from_bytes(hashlib.sha256(blinding_factor_preimage).digest(), byteorder='big')
        ephemeral_key = (ephemeral_key * blinding_factor) % ECPrivkey.ORDER
    filler = generate_header_padding("rho", num_hops, HOP_DATA_SIZE, hop_shared_secrets)
    padding_key = generate_key("pad", session_key.get_secret_bytes())
    padding_bytes = generate_cipher_stream(padding_key, ROUTING_INFO_SIZE)
    mix_header = bytearray(padding_bytes)
    next_hmac = bytes([0] * HMAC_SIZE)
    for i in range(num_hops - 1, -1, -1):
        rho_key = generate_key("rho", hop_shared_secrets[i])
        mu_key = generate_key("mu", hop_shared_secrets[i])
        stream_bytes = generate_cipher_stream(rho_key, NUM_STREAM_BYTES)
        right_shift(mix_header, HOP_DATA_SIZE)
        hop_data = bytearray(hops_data[i])
        hop_data.extend(next_hmac)
        for j in range(min(len(hop_data), HOP_DATA_SIZE)):
            mix_header[j] = hop_data[j]
        xor(mix_header, mix_header, stream_bytes[:ROUTING_INFO_SIZE])
        if i == num_hops - 1:
            filler_offset = ROUTING_INFO_SIZE - len(filler)
            for j in range(len(filler)):
                mix_header[filler_offset + j] = filler[j]
        packet = mix_header + assoc_data
        next_hmac = calc_mac(mu_key, packet)
    ephemeral_pubkey = session_key.get_public_key().get_public_key_bytes()
    version = bytes([0])
    packet = version + ephemeral_pubkey + bytes(mix_header) + next_hmac
    return packet

def parse_input(file_path: str) -> Dict[str, Any]:
    with open(file_path, 'r') as f:
        return json.load(f)

def process_input(input_data: Dict[str, Any]) -> Tuple[ECPrivkey, bytes, List[ECPubkey], List[bytes]]:
    session_key_bytes = hex_to_bytes(input_data["session_key"])
    session_key = ECPrivkey(session_key_bytes)
    assoc_data = hex_to_bytes(input_data["associated_data"])
    pubkeys = []
    payloads = []
    for hop in input_data["hops"]:
        pubkey_bytes = hex_to_bytes(hop["pubkey"])
        pubkey = ECPubkey(pubkey_bytes)
        pubkeys.append(pubkey)
        payload = hex_to_bytes(hop["payload"])
        payloads.append(payload)
    return session_key, assoc_data, pubkeys, payloads

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output_directory> <input_file>")
        sys.exit(1)
    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    input_data = parse_input(input_file)
    session_key, assoc_data, pubkeys, payloads = process_input(input_data)
    onion_packet = create_onion_packet(pubkeys, session_key, payloads, assoc_data)
    output_path = os.path.join(output_dir, "output.txt")
    with open(output_path, "w") as f:
        f.write(bytes_to_hex(onion_packet))
    print(f"Onion packet written to {output_path}")

if __name__ == "__main__":
    main()
