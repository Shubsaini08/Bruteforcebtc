import os
import ecdsa
import base58
import multiprocessing
from Crypto.Hash import SHA256, RIPEMD160

# Function to generate Bitcoin addresses from a private key
def generate_bitcoin_address(private_key):
    fullkey = '80' + private_key.hex()
    sha256a = SHA256.new(bytes.fromhex(fullkey)).hexdigest()
    sha256b = SHA256.new(bytes.fromhex(sha256a)).hexdigest()
    WIF = base58.b58encode(bytes.fromhex(fullkey + sha256b[:8]))

    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    public_key = '04' + x.to_bytes(32, 'big').hex() + y.to_bytes(32, 'big').hex()

    compressed_public_key = '02' if y % 2 == 0 else '03'
    compressed_public_key += x.to_bytes(32, 'big').hex()

    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    hash160 = RIPEMD160.new()
    hash160.update(SHA256.new(bytes.fromhex(compressed_public_key)).digest())
    public_key_hash = '00' + hash160.hexdigest()
    checksum = SHA256.new(SHA256.new(bytes.fromhex(public_key_hash)).digest()).hexdigest()[:8]
    compressed_p2pkh_address = base58.b58encode(bytes.fromhex(public_key_hash + checksum))

    return {
        'private_key': private_key.hex(),
        'WIF': WIF.decode(),
        'public_key': public_key,
        'compressed_public_key': compressed_public_key,
        'p2pkh_address': p2pkh_address.decode(),
        'compressed_p2pkh_address': compressed_p2pkh_address.decode(),
    }

# Function to save data to file
def save_to_file(filename, data):
    with open(filename, 'a') as f:
        f.write(data + "\n")

# Function to generate keys in a specific range
def generate_range_keys(start, end):
    for i in range(start, end):
        private_key = i.to_bytes(32, 'big')
        address_info = generate_bitcoin_address(private_key)
        output = f"Private Key: {address_info['private_key']}\n" \
                 f"Public Address: {address_info['p2pkh_address']}\n" \
                 f"Compressed Address: {address_info['compressed_p2pkh_address']}\n\n"
        save_to_file('puzfound.txt', output)

# Function to hunt puzzles within a given range
def hunt_puzzles(puzzle_range_start, puzzle_range_end):
    start = int(puzzle_range_start, 16)
    end = int(puzzle_range_end, 16)
    generate_range_keys(start, end)

# Main function to handle user choices
def main():
    print("Select an option:")
    print("1. Generate a specific number of keys")
    print("2. Start generating random keys (press Ctrl+C to stop)")
    print("3. Generate keys in a range")
    print("4. Hunt for puzzles")

    choice = input("Enter your choice: ")

    if choice == '1':
        num_keys = int(input("Enter the number of keys to generate: "))
        generate_range_keys(1, num_keys)

    elif choice == '2':
        print("Press Ctrl+C to stop.")
        try:
            while True:
                private_key = os.urandom(32)
                address_info = generate_bitcoin_address(private_key)
                output = f"Private Key: {address_info['private_key']}\n" \
                         f"Public Address: {address_info['p2pkh_address']}\n" \
                         f"Compressed Address: {address_info['compressed_p2pkh_address']}\n\n"
                save_to_file('puzfound.txt', output)
        except KeyboardInterrupt:
            print("\nRandom key generation stopped.")

    elif choice == '3':
        start = int(input("Enter start of range (hex): "), 16)
        end = int(input("Enter end of range (hex): "), 16)
        num_workers = multiprocessing.cpu_count()
        ranges = [(start + i*(end-start)//num_workers, start + (i+1)*(end-start)//num_workers) for i in range(num_workers)]
        processes = [multiprocessing.Process(target=generate_range_keys, args=(r[0], r[1])) for r in ranges]
        for p in processes:
            p.start()
        for p in processes:
            p.join()

    elif choice == '4':
        puzzle_choice = input("Select puzzle range:\n1. Puzzle 67\n2. Puzzle 76\nEnter your choice: ")
        if puzzle_choice == '1':
            hunt_puzzles("0000000000000000000000000000000000000000000000040000000000000000", 
                         "000000000000000000000000000000000000000000000007ffffffffffffffff")
        elif puzzle_choice == '2':
            hunt_puzzles("0000000000000000000000000000000000000000000008000000000000000000", 
                         "000000000000000000000000000000000000000000000fffffffffffffffffff")
        else:
            print("Invalid choice for puzzle.")
    
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()

