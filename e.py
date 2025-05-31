from eth_keys import keys
from eth_utils import keccak
from tqdm import tqdm
import os

def private_key_from_int(i):
    return i.to_bytes(32, 'big')

def get_address(private_key_bytes):
    pk = keys.PrivateKey(private_key_bytes)
    pub_key_bytes = pk.public_key.to_bytes()
    address = keccak(pub_key_bytes[1:])[-20:]
    return "0x" + address.hex(), pk.to_hex()

# Target address (lowercase)
target_address = "0x9becc0320f317e2137bb3616c064b78b68d99919"

# Resume from last saved index
progress_file = "progress.txt"
if os.path.exists(progress_file):
    with open(progress_file, "r") as f:
        start = int(f.read().strip())
else:
    start = 1

# Display target once
print(f"Target Address : {target_address}")
print(f"Resuming From  : {start}\n")

# Initialize scan
found = False
private_key_found = "N/A"
mnemonic_found = "N/A"  # Not used unless using mnemonic-based cracking

try:
    i = start
    with tqdm(total=0, initial=i, dynamic_ncols=True, unit=" keys", desc="Scanning") as pbar:
        while True:
            private_key_bytes = private_key_from_int(i)
            address, priv_hex = get_address(private_key_bytes)

            if address.lower() == target_address:
                found = True
                private_key_found = priv_hex

                with open("found.txt", "w") as f:
                    f.write(f"Private Key: {priv_hex}\nAddress: {address}\nIndex: {i}\n")

                print("\n🎯 Match Found!")
                print(f"Private Key : {priv_hex}")
                print(f"Address     : {address}")
                print(f"Index       : {i}")
                break

            i += 1
            pbar.update(1)
            pbar.set_postfix({
                "Scanned": i,
                "Found": "✅" if found else "❌",
                "PrivateKey": private_key_found[-8:] if found else "N/A",
                "Mnemonic": mnemonic_found
            })

except KeyboardInterrupt:
    print("\n⛔ Interrupted. Saving progress...")
    with open(progress_file, "w") as f:
        f.write(str(i))
