from mnemonic import Mnemonic
from eth_account import Account
from tqdm import tqdm
import os

# Set your target Ethereum address (lowercase for match)
target_address = "0x9becc0320f317e2137bb3616c064b78b68d99919"

# Resume scan
progress_file = "progress_mnemonic.txt"
if os.path.exists(progress_file):
    with open(progress_file, "r") as f:
        start = int(f.read().strip())
else:
    start = 0

# Initialize
mnemo = Mnemonic("english")
found = False
print(f"Target Address : {target_address}")
print(f"Starting From  : {start}\n")

try:
    i = start
    with tqdm(total=0, initial=i, dynamic_ncols=True, unit=" mnemonics", desc="Scanning") as pbar:
        while True:
            mnemonic_phrase = mnemo.generate(strength=128)  # 12-word BIP39 mnemonic
            seed = mnemo.to_seed(mnemonic_phrase)
            acct = Account.from_mnemonic(mnemonic_phrase)
            eth_address = acct.address.lower()

            if eth_address == target_address:
                found = True
                print("\n🎯 MATCH FOUND!")
                print(f"Mnemonic   : {mnemonic_phrase}")
                print(f"Address    : {eth_address}")
                print(f"PrivateKey : {acct.key.hex()}")
                print(f"Index      : {i}")

                with open("found.txt", "w") as f:
                    f.write(f"Mnemonic: {mnemonic_phrase}\n")
                    f.write(f"Address : {eth_address}\n")
                    f.write(f"Private Key: {acct.key.hex()}\n")
                    f.write(f"Index   : {i}\n")
                break

            i += 1
            pbar.update(1)
            pbar.set_postfix({
                "Scanned": i,
                "Found": "✅" if found else "❌",
                "Last": eth_address[-6:]
            })

except KeyboardInterrupt:
    print("\n⛔ Interrupted. Saving progress...")
    with open(progress_file, "w") as f:
        f.write(str(i))
