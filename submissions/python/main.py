#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import hmac
from binascii import unhexlify, hexlify
from Cryptodome.Cipher import ChaCha20
from Cryptodome.Random import get_random_bytes
import secp256k1

# Constants from BOLT 04
ONION_VERSION = 0x00
HOP_DATA_LEN = 1300
HOP_PAYLOAD_LEN = 65  # 1 byte realm + 32 byte short_channel_id + 4 byte amt_to_forward + 4 byte outgoing_cltv_value + 24 byte padding
RHO = b'rho'
MU = b'mu'
UM = b'um'
PAD_LEN = HOP_DATA_LEN - HOP_PAYLOAD_LEN

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
    """Generate ChaCha20 cipher stream"""
    nonce = bytes(12)  # Zero nonce as per BOLT 04
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
        # Initialize variables
        ephemeral_keys = []
        shared_secrets = []
        hop_payloads = []
        filler = b''
        
        # Process hops in reverse order
        for i in reversed(range(self.num_hops)):
            hop = self.hops[i]
            
            # Generate ephemeral key
            if i == self.num_hops - 1:
                # First hop (last in reverse) uses session key
                ephemeral_key = self.session_key
            else:
                # Subsequent hops use previous blinding factor
                privkey = secp256k1.PrivateKey()
                ephemeral_key = privkey.private_key
                
            ephemeral_keys.insert(0, ephemeral_key)
            
            # Derive shared secret
            pubkey = secp256k1.PublicKey(unhexlify(hop['pubkey']), raw=True)
            ecdh_point = secp256k1.PrivateKey(ephemeral_key).ecdh(unhexlify(hop['pubkey']))
            shared_secret = hashlib.sha256(ecdh_point).digest()
            shared_secrets.insert(0, shared_secret)
            
            # Generate keys
            rho_key = generate_key(RHO, shared_secret)
            mu_key = generate_key(MU, shared_secret)
            
            # Process payload
            payload = unhexlify(hop['payload'])
            if i == self.num_hops - 1:
                # Last hop has empty HMAC
                hmac_val = bytes(32)
            else:
                # Generate HMAC for next hop
                next_hop_payload = hop_payloads[0]
                hmac_val = hmac.new(mu_key, next_hop_payload, hashlib.sha256).digest()
            
            # Create hop data (payload + HMAC)
            hop_data = payload + hmac_val
            assert len(hop_data) <= HOP_PAYLOAD_LEN, "Payload too large"
            hop_data = hop_data.ljust(HOP_PAYLOAD_LEN, b'\x00')
            
            # Pad to HOP_DATA_LEN
            padding = bytes(PAD_LEN)
            hop_data_padded = hop_data + padding
            
            # Encrypt with ChaCha20
            stream = generate_cipher_stream(rho_key, HOP_DATA_LEN)
            encrypted_hop_data = xor_bytes(hop_data_padded, stream)
            
            hop_payloads.insert(0, encrypted_hop_data)
            
            # Generate blinding factor for next hop
            if i > 0:
                um_key = generate_key(UM, shared_secret)
                ephemeral_pubkey = secp256k1.PrivateKey(ephemeral_key).pubkey.serialize()
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
        first_ephemeral_pubkey = secp256k1.PrivateKey(ephemeral_keys[0]).pubkey.serialize()
        onion_packet = bytes([ONION_VERSION]) + first_ephemeral_pubkey + onion_payload
        
        # Generate HMAC for entire packet
        mu_key_first = generate_key(MU, shared_secrets[0])
        packet_hmac = hmac.new(mu_key_first, onion_packet, hashlib.sha256).digest()
        
        # Final onion packet
        final_onion = onion_packet + packet_hmac
        
        return hexlify(final_onion).decode('ascii')

def main():
    if len(sys.argv) != 3:
        print("Usage: python onion_builder.py <output_directory> <input_file>")
        sys.exit(1)
    
    output_dir = sys.argv[1]
    input_file = sys.argv[2]
    
    # Read input JSON
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Build onion
    builder = OnionBuilder(data['session_key'], data['associated_data'], data['hops'])
    onion = builder.build_onion()
    
    # Write output
    output_file = os.path.join(output_dir, 'output.txt')
    with open(output_file, 'w') as f:
        f.write(onion)

if __name__ == '__main__':
    main()