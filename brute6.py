import random
import hashlib
import ecdsa
import binascii
import base58
from bitcoinaddress import Wallet
from blocksmith import KeyGenerator

def generate_private_key():
    # Generate a random 32 bytes private key in hexadecimal format
    return ''.join(random.choices('0123456789abcdef', k=64))

def private_key_to_address(private_key):
    # Convert hexadecimal private key to bytes
    private_key_bytes = binascii.unhexlify(private_key)
    # Generate the signing key from the private key bytes
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    # Generate the verifying key for the public key
    vk = sk.verifying_key
    # Compressing the public key
    compressed_public_key = b'\x02' + vk.to_string()[:32] if (vk.to_string()[32:64][-1] % 2 == 0) else b'\x03' + vk.to_string()[:32]
    # Perform SHA-256 hashing on the compressed public key
    sha256_hash = hashlib.sha256(compressed_public_key).digest()
    # Perform RIPEMD-160 hashing on the result of the SHA-256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    network_byte = b'\x00'  # Mainnet network byte
    extended_ripemd160_hash = network_byte + ripemd160.digest()
    # Double SHA-256 to get the checksum
    checksum = hashlib.sha256(hashlib.sha256(extended_ripemd160_hash).digest()).digest()[:4]
    # Adding the checksum to the extended RIPEMD-160 hash
    final_key = extended_ripemd160_hash + checksum
    # Encoding the final key in Base58
    return base58.b58encode(final_key).decode('utf-8')

def search_keys_in_range(start, end):
    with open("btcput.txt", "a") as output_file, open("bitcoin.txt", "a") as matched_file, open("list5.txt", "r") as baddress_file:
        baddress_list = baddress_file.read().splitlines()
        for i in range(start, end+1):
            private_key = hex(i)[2:].zfill(64)  # Convert integer to hexadecimal
            address = private_key_to_address(private_key)
            if address in baddress_list:
                output_file.write(f"Private Key: {private_key}\nAddress: {address}\n")
                matched_file.write(f"Private Key: {private_key}\nAddress: {address}\n")
                print(f"Private Key #{i-start+1}: {private_key}")
            else:
                output_file.write(f"Private Key: {private_key}\nAddress: {address}\n")
                print(f"Private Key #{i-start+1}: {private_key}")

def main():
    while True:
        print("\n1. Generate a new private key and address")
        print("2. Search for keys in a range")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            wallet = Wallet()
            print("\nPrivate Key:", wallet.private.wif)
            print("Address:", wallet.address.mainnet)

        elif choice == '2':
            start_hex = input("Enter the starting hexadecimal value: ")
            end_hex = input("Enter the ending hexadecimal value: ")
            start = int(start_hex, 16)
            end = int(end_hex, 16)
            search_keys_in_range(start, end)

        elif choice == '3':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()

