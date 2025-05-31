from eth_keys import keys
from eth_utils import keccak
import os

def private_key_from_int(i):
    b = i.to_bytes(32, 'big')
    if len(b) != 32:
        raise ValueError(f"Invalid key length: {len(b)}")
    return b

def get_address(private_key_bytes):
    pk = keys.PrivateKey(private_key_bytes)
    pub_key_bytes = pk.public_key.to_bytes()
    address = keccak(pub_key_bytes[1:])[-20:]
    return "0x" + address.hex(), pk.to_hex()

# Set your target Ethereum address here (converted to lowercase for matching)
target_address = "0x9becc0320f317e2137bb3616c064b78b68d99919"

# File to track progress
progress_file = "progress.txt"
if os.path.exists(progress_file):
    with open(progress_file, "r") as f:
        start = int(f.read().strip())
else:
    start = 1  # Start from 1, never 0

print(f"Resuming from: {start}")

try:
    i = start
    while True:
        private_key_bytes = private_key_from_int(i)
        address, priv_hex = get_address(private_key_bytes)

        if i % 100000 == 0:
            print(f"Checked {i} keys... Last address: {address}")

        if address.lower() == target_address:
            print("Match found!")
            with open("found.txt", "w") as f:
                f.write(f"Private Key: {priv_hex}\nAddress: {address}\nIndex: {i}\n")
            break

        i += 1

except KeyboardInterrupt:
    print("Stopped manually. Saving progress...")
    with open(progress_file, "w") as f:
        f.write(str(i))
        
