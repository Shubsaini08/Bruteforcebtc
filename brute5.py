import blocksmith
import os
import ecdsa
from hashlib import sha256, new as new_hash
import base58

def generate_bitcoin_address(private_key):
    # Generate WIF
    fullkey = '80' + private_key.hex()
    sha256a = sha256(bytes.fromhex(fullkey)).hexdigest()
    sha256b = sha256(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8])).decode()

    # Get public key
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    # Get compressed public key
    compressed_public_key = ('02' if y % 2 == 0 else '03') + x.to_bytes(32, 'big').hex()

    # Get P2PKH address
    hash160 = new_hash('ripemd160')
    hash160.update(sha256(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = sha256(sha256(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum)).decode()

    # Get compressed P2PKH address
    hash160 = new_hash('ripemd160')
    hash160.update(sha256(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = sha256(sha256(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum)).decode()

    return WIF, p2pkh_address, compressed_p2pkh_address

address_1 = str(input('Enter the btc address: '))
sert = 0

with open('brute5.txt', 'w') as file:
    while True:
        paddress_1aphrase = blocksmith.KeyGenerator()
        paddress_1aphrase.seed_input('qwertyuiopasdfghjklzxcvbnm1234567890')
        private_Key = paddress_1aphrase.generate_key()
        private_key_bytes = bytes.fromhex(private_Key)
        
        WIF, p2pkh_address, compressed_p2pkh_address = generate_bitcoin_address(private_key_bytes)

        sert += 1
        
        if address_1 == p2pkh_address or address_1 == compressed_p2pkh_address:
            output = (
                "We found it!\n"
                f"Private Key: {private_Key}\n"
                f"WIF: {WIF}\n"
                f"P2PKH Address: {p2pkh_address}\n"
                f"Compressed P2PKH Address: {compressed_p2pkh_address}\n"
            )
            print(output)
            file.write(output)
            break
        else:
            output = (
                f"Trying Private Key: {private_Key}\n"
                f"WIF: {WIF}\n"
                f"P2PKH Address: {p2pkh_address}\n"
                f"Compressed P2PKH Address: {compressed_p2pkh_address}\n"
            )
            print(output)
            file.write(output)

