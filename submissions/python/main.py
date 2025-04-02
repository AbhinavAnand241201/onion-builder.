#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import hmac
from binascii import unhexlify, hexlify
from Cryptodome.Cipher import ChaCha20
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import number_to_string

# Constants from BOLT 04
ONION_VERSION = 0x00
HOP_DATA_LEN = 1300
HOP_PAYLOAD_LEN = 65  # 1 byte length + 32 byte HMAC + 32 byte payload (max)
RHO = b'rho'
MU = b'mu'
UM = b'um'

def generate_key(key_type, secret):
    """Generate key using HKDF with SHA256"""
    return hashlib.sha256(key_type + secret).digest()

def generate_filler(rho_key, num_hops):
    """Generate filler bytes using pseudo-random stream"""
    filler = bytearray()
    stream = generate_cipher_stream(rho_key, HOP_DATA_LEN * (num_hops - 1))
    for i in range(num_hops - 1):
        start = (num_hops - i - 2) * HOP_DATA_LEN
        filler += stream[start:start + HOP_DATA_LEN]
    return bytes(filler)

def generate_cipher_stream(key, length):
    """Generate ChaCha20 cipher stream with 96-bit null nonce"""
    nonce = bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(bytes(length))

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))

class OnionBuilder:
    def __init__(self, session_key, associated_data, hops):
        self.session_key = unhexlify(session_key)
        self.associated_data = unhexlify(associated_data)
        self.hops = hops
        self.num_hops = len(hops)
        
    def build_onion(self):
        ephemeral_keys = []
        shared_secrets = []
        onion_payload = bytearray(HOP_DATA_LEN)
        
        # Initialize with random bytes
        initial_padding = generate_cipher_stream(self.session_key, HOP_DATA_LEN)
        onion_payload[:] = initial_padding
        
        # Process hops in reverse order
        for i in reversed(range(self.num_hops)):
            hop = self.hops[i]
            payload = unhexlify(hop['payload'])
            
            # Validate payload size
            if len(payload) > 32:  # Max payload per BOLT-04
                raise ValueError(f"Payload for hop {i} too large ({len(payload)} > 32 bytes)")
            
            # Generate ephemeral key
            if i == self.num_hops - 1:
                privkey = SigningKey.from_string(self.session_key, curve=SECP256k1)
            else:
                privkey = SigningKey.from_string(ephemeral_key, curve=SECP256k1)
            
            ephemeral_key = privkey.to_string()
            ephemeral_keys.insert(0, privkey.get_verifying_key())
            
            # Derive shared secret
            peer_pubkey = VerifyingKey.from_string(unhexlify(hop['pubkey']), curve=SECP256k1)
            shared_secret = ecdh(privkey, peer_pubkey)
            shared_secret = hashlib.sha256(shared_secret).digest()
            shared_secrets.insert(0, shared_secret)
            
            # Generate keys
            rho_key = generate_key(RHO, shared_secret)
            mu_key = generate_key(MU, shared_secret)
            um_key = generate_key(UM, shared_secret)
            
            # Create hop data
            hmac_val = bytes(32) if i == self.num_hops - 1 else hmac.new(
                mu_key, bytes(onion_payload), hashlib.sha256).digest()
            
            hop_data = bytes([len(payload)]) + payload + hmac_val
            hop_data = hop_data.ljust(HOP_PAYLOAD_LEN, b'\x00')
            
            # Apply filler for intermediate hops
            if i > 0:
                filler = generate_filler(rho_key, self.num_hops - i)
                onion_payload = xor_bytes(onion_payload, filler)
            
            # Insert hop data
            start_pos = i * HOP_PAYLOAD_LEN
            onion_payload[start_pos:start_pos+HOP_PAYLOAD_LEN] = hop_data
            
            # Encrypt
            stream = generate_cipher_stream(rho_key, HOP_DATA_LEN)
            onion_payload = xor_bytes(onion_payload, stream)
            
            # Generate blinding factor
            if i > 0:
                bf_input = ephemeral_keys[0].to_string() + hop_data[:HOP_PAYLOAD_LEN]
                ephemeral_key = hmac.new(um_key, bf_input, hashlib.sha256).digest()
        
        # Final packet assembly
        first_ephemeral_pubkey = ephemeral_keys[0].to_string()
        onion_packet = bytes([ONION_VERSION]) + first_ephemeral_pubkey + onion_payload
        packet_hmac = hmac.new(
            generate_key(MU, shared_secrets[0]), 
            onion_packet, 
            hashlib.sha256
        ).digest()
        
        return hexlify(onion_packet + packet_hmac).decode('ascii')

def ecdh(private_key, peer_pubkey):
    """Perform ECDH key exchange"""
    point = private_key.privkey.secret_multiplier * peer_pubkey.pubkey.point
    return number_to_string(point.x(), SECP256k1.order)

def main():
    if len(sys.argv) != 3:
        print("Usage: python main.py <output_directory> <input_file>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Validate input
    required_fields = ['session_key', 'associated_data', 'hops']
    for field in required_fields:
        if field not in data:
            print(f"Error: Missing required field '{field}'")
            sys.exit(1)
    
    try:
        builder = OnionBuilder(data['session_key'], data['associated_data'], data['hops'])
        onion = builder.build_onion()
        
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, 'output.txt')
        with open(output_path, 'w') as f:
            f.write(onion)
        print(f"Success: Onion packet generated at {output_path}")
    except ValueError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()