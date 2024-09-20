import hashlib
import os
import random
import multiprocessing
from functools import lru_cache
from Crypto.Hash import SHA256, RIPEMD160
import base58
import ecdsa

# Constants for Bech32 encoding
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

# Function to convert private key to WIF format
def private_key_to_wif(key_hex, compressed=False):
    key_hex = '80' + key_hex
    if compressed:
        key_hex += '01'
    key_bytes = bytes.fromhex(key_hex)
    sha256_1 = SHA256.new(key_bytes).digest()
    sha256_2 = SHA256.new(sha256_1).digest()
    checksum = sha256_2[:4]
    return base58.b58encode(bytes.fromhex(key_hex + checksum.hex())).decode('utf-8')

# Function to generate public key from private key
def generate_key(private_key, compressed=False):
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x_coord = vk.to_string()[:32]
    y_coord = vk.to_string()[32:64]
    prefix = b'\x02' if int.from_bytes(y_coord, 'big') % 2 == 0 else b'\x03'
    return prefix + x_coord if compressed else b'\x04' + vk.to_string()

# Caching the computation of P2PKH address
@lru_cache(maxsize=None)
def compute_p2pkh_address(public_key):
    sha256_1 = SHA256.new(public_key).digest()
    ripemd160 = RIPEMD160.new(sha256_1).digest()
    network_byte = b'\x00' + ripemd160
    sha256_2 = SHA256.new(network_byte).digest()
    checksum = SHA256.new(sha256_2).digest()[:4]
    return base58.b58encode(network_byte + checksum).decode('utf-8')

# Bech32 encoding functions
def bech32_polymod(values):
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# Function to convert bits
def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

# Function to compute various address types
def public_key_to_bech32_address(public_key):
    witness_program = RIPEMD160.new(SHA256.new(public_key).digest()).digest()
    return bech32_encode('bc', [0] + convertbits(witness_program, 8, 5))

def compute_p2wpkh_address(public_key):
    witness_program = RIPEMD160.new(SHA256.new(public_key).digest()).digest()
    return bech32_encode('bc', [0] + convertbits(witness_program, 8, 5))

def compute_p2sh_address(public_key):
    sha256_1 = SHA256.new(public_key).digest()
    ripemd160 = RIPEMD160.new(sha256_1).digest()
    redeem_script = b'\x00' + bytes([len(ripemd160)]) + ripemd160
    sha256_2 = SHA256.new(redeem_script).digest()
    ripemd160_2 = RIPEMD160.new(sha256_2).digest()
    address_bytes = b'\x05' + ripemd160_2
    checksum = SHA256.new(SHA256.new(address_bytes).digest()).digest()[:4]
    return base58.b58encode(address_bytes + checksum).decode('utf-8')

# Worker function to generate keys and addresses
def process_key(private_key_hex):
    wif = private_key_to_wif(private_key_hex, True)
    public_key_compressed = generate_key(private_key_hex, True)
    public_key_uncompressed = generate_key(private_key_hex, False)

    p2pkh_address_compressed = compute_p2pkh_address(public_key_compressed)
    p2pkh_address_uncompressed = compute_p2pkh_address(public_key_uncompressed)
    bech32_address = public_key_to_bech32_address(public_key_compressed)
    p2wpkh_address_compressed = compute_p2wpkh_address(public_key_compressed)
    p2wpkh_address_uncompressed = compute_p2wpkh_address(public_key_uncompressed)
    p2sh_address = compute_p2sh_address(public_key_compressed)

    return (private_key_hex, wif, p2pkh_address_compressed, p2pkh_address_uncompressed,
            p2wpkh_address_compressed, p2wpkh_address_uncompressed,
            bech32_address, p2sh_address)

# Main function to execute the key generation and address computation
def main():
    print("Choose an option:")
    print("1. Hunt in range")
    print("2. Random")
    option = input("Enter your choice (1 or 2): ")

    if option == '1':
        private_key_range_start = 0x7600000000000000
        private_key_range_end = 0x8000000000000000
        private_keys_hex = (format(i, '064x') for i in range(private_key_range_start, private_key_range_end))
    elif option == '2':
        private_keys_hex = (format(random.randint(1, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140), '064x') for _ in range(99999))
    else:
        print("Invalid option selected.")
        return

    os.makedirs('output', exist_ok=True)
    with open('output/keys.txt', 'w') as f:
        with multiprocessing.Pool(processes=multiprocessing.cpu_count() * 2) as pool:
            for result in pool.imap(process_key, private_keys_hex, chunksize=1000):
                f.write(f"Private Key: {result[0]}\n")
                f.write(f"WIF: {result[1]}\n")
                f.write(f"P2PKH (Compressed): {result[2]}\n")
                f.write(f"P2PKH (Uncompressed): {result[3]}\n")
                f.write(f"P2WPKH (Compressed): {result[4]}\n")
                f.write(f"P2WPKH (Uncompressed): {result[5]}\n")
                f.write(f"Bech32 Address: {result[6]}\n")
                f.write(f"P2SH Address: {result[7]}\n\n")
                print(result[0])

if __name__ == "__main__":
    main()


