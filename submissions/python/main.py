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
HOP_PAYLOAD_LEN = 1300
RHO = b'rho'
MU = b'mu'
UM = b'um'

def generate_key(key_type, secret):
    """Generate key using HKDF with SHA256"""
    return hashlib.sha256(key_type + secret).digest()

def generate_filler(key, num_hops, hop_size):
    """Generate filler bytes for the onion packet"""
    filler = bytearray()
    stream = generate_cipher_stream(key, num_hops * hop_size)
    for i in range(num_hops - 1):
        start = (num_hops - i - 1) * hop_size
        filler += stream[start:start + hop_size]
    return bytes(filler)

def generate_cipher_stream(key, length):
    """Generate ChaCha20 cipher stream with 96-bit null nonce"""
    nonce = bytes(12)  # 96-bit null nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.encrypt(bytes(length))

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))

def serialize_pubkey(pubkey):
    """Serialize public key in compressed format"""
    return pubkey.to_string("compressed")

def ecdh(private_key, peer_pubkey_bytes):
    """Perform ECDH key exchange using secp256k1"""
    # Parse peer's public key
    peer_pubkey = VerifyingKey.from_string(peer_pubkey_bytes, curve=SECP256k1)
    
    # Calculate shared secret
    point = private_key.privkey.secret_multiplier * peer_pubkey.pubkey.point
    return number_to_string(point.x(), SECP256k1.order)

class OnionBuilder:
    def __init__(self, session_key, associated_data, hops):
        self.session_key = unhexlify(session_key)
        self.associated_data = unhexlify(associated_data)
        self.hops = hops
        self.num_hops = len(hops)
        
    def build_onion(self):
        ephemeral_keys = []
        shared_secrets = []
        hop_payloads = []
        
        # Process hops in reverse order
        for i in reversed(range(self.num_hops)):
            hop = self.hops[i]
            
            # Generate ephemeral key
            if i == self.num_hops - 1:
                privkey = SigningKey.from_string(self.session_key, curve=SECP256k1)
            else:
                privkey = SigningKey.from_string(ephemeral_key, curve=SECP256k1)
            
            ephemeral_key = privkey.to_string()
            ephemeral_keys.insert(0, ephemeral_key)
            
            # Derive shared secret
            peer_pubkey_bytes = unhexlify(hop['pubkey'])
            shared_secret = ecdh(privkey, peer_pubkey_bytes)
            shared_secret = hashlib.sha256(shared_secret).digest()
            shared_secrets.insert(0, shared_secret)
            
            # Generate keys
            rho_key = generate_key(RHO, shared_secret)
            mu_key = generate_key(MU, shared_secret)
            
            # Process payload
            payload = unhexlify(hop['payload'])
            if i == self.num_hops - 1:
                hmac_val = bytes(32)  # Final hop has empty HMAC
            else:
                next_hop_payload = hop_payloads[0]
                hmac_val = hmac.new(mu_key, next_hop_payload, hashlib.sha256).digest()
            
            # Create hop data (payload + HMAC)
            hop_data = payload + hmac_val
            hop_data = hop_data.ljust(HOP_PAYLOAD_LEN, b'\x00')
            
            # Encrypt with ChaCha20
            stream = generate_cipher_stream(rho_key, HOP_DATA_LEN)
            encrypted_hop_data = xor_bytes(hop_data, stream[:len(hop_data)])
            
            hop_payloads.insert(0, encrypted_hop_data)
            
            # Generate blinding factor for next hop
            if i > 0:
                um_key = generate_key(UM, shared_secret)
                ephemeral_pubkey = serialize_pubkey(privkey.get_verifying_key())
                bf_input = ephemeral_pubkey + hop_data[:HOP_PAYLOAD_LEN]
                blinding_factor = hmac.new(um_key, bf_input, hashlib.sha256).digest()
                ephemeral_key = blinding_factor
        
        # Generate filler
        filler = generate_filler(rho_key, self.num_hops, HOP_DATA_LEN)
        
        # Build final onion
        onion_payload = bytes(HOP_DATA_LEN * self.num_hops)
        for i in range(self.num_hops):
            start = i * HOP_DATA_LEN
            end = start + HOP_DATA_LEN
            onion_payload = onion_payload[:start] + hop_payloads[i] + onion_payload[end:]
        
        # Apply filler
        onion_payload = xor_bytes(onion_payload, filler)
        
        # Prepend version and first ephemeral key
        first_privkey = SigningKey.from_string(ephemeral_keys[0], curve=SECP256k1)
        first_ephemeral_pubkey = serialize_pubkey(first_privkey.get_verifying_key())
        onion_packet = bytes([ONION_VERSION]) + first_ephemeral_pubkey + onion_payload
        
        # Generate HMAC for entire packet
        mu_key_first = generate_key(MU, shared_secrets[0])
        packet_hmac = hmac.new(mu_key_first, onion_packet, hashlib.sha256).digest()
        
        return hexlify(onion_packet + packet_hmac).decode('ascii')

def main():
    if len(sys.argv) != 3:
        print("Usage: python main.py <output_directory> <input_file>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Validate input structure
    required_fields = ['session_key', 'associated_data', 'hops']
    for field in required_fields:
        if field not in data:
            print(f"Error: Missing required field '{field}' in input JSON")
            sys.exit(1)
    
    builder = OnionBuilder(data['session_key'], data['associated_data'], data['hops'])
    onion = builder.build_onion()
    
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'output.txt')
    with open(output_path, 'w') as f:
        f.write(onion)
    print(f"Success: Onion packet generated at {output_path}")

if __name__ == '__main__':
    main()