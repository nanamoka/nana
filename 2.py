from decimal import Decimal, getcontext
import hashlib
import ecdsa
import os
import sys

getcontext().prec = 100

# ============ CONFIG ============
ADDRESSES_PER_PAGE = 45
PERCENT = Decimal("0.30")       # <-- changed from 0.4999 to 0.30
PAGES_AROUND = 150
PREFIX_LEN = 9                  # <-- changed from 8 to 9
PREFIX_FILE = "prefix_matches.txt"
FOUND_FILE = "FOUND.txt"
# ================================


def int_to_bytes32(x):
    return x.to_bytes(32, 'big')


def privkey_to_pubkey_compressed(priv):
    sk = ecdsa.SigningKey.from_secret_exponent(priv, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if (y % 2 == 0) else b'\x03'
    return prefix + int_to_bytes32(x)


def hash160(data):
    sha = hashlib.sha256(data).digest()
    try:
        rip = hashlib.new('ripemd160')
        rip.update(sha)
        return rip.digest()
    except ValueError:
        from Crypto.Hash import RIPEMD160
        h = RIPEMD160.new()
        h.update(sha)
        return h.digest()


def base58_encode(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b, 'big')
    res = ''
    while n > 0:
        n, r = divmod(n, 58)
        res = alphabet[r] + res
    for byte in b:
        if byte == 0:
            res = '1' + res
        else:
            break
    return res


def base58check(payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def priv_to_address_compressed(priv):
    pub = privkey_to_pubkey_compressed(priv)
    h160 = hash160(pub)
    payload = b'\x00' + h160
    return base58check(payload)


def parse_number(s):
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def load_ranges(path="range.txt"):
    ranges = []
    current_puzzle = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if "Puzzle" in line:
                    try:
                        current_puzzle = int(line.split("Puzzle")[1].strip().split()[0])
                    except Exception:
                        pass
                continue
            parts = line.split()
            if len(parts) != 2:
                continue
            ranges.append((current_puzzle, parse_number(parts[0]), parse_number(parts[1])))
            current_puzzle = None
    return ranges


def load_addresses(path="address.txt"):
    full = set()
    prefixes = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                full.add(line)
                prefixes.add(line[:PREFIX_LEN])
    return full, prefixes


def scan_range(puzzle_num, start, end, full_targets, prefixes, idx, total):
    range_size = end - start + 1
    offset = int(Decimal(range_size - 1) * PERCENT)
    central_key = start + offset
    central_page = offset // ADDRESSES_PER_PAGE + 1

    first_page = max(1, central_page - PAGES_AROUND)
    last_page = central_page + PAGES_AROUND

    first_offset = (first_page - 1) * ADDRESSES_PER_PAGE
    last_offset = min(range_size - 1, last_page * ADDRESSES_PER_PAGE - 1)

    label = f"PUZZLE {puzzle_num}" if puzzle_num is not None else f"RANGE #{idx}"

    print(f"\n{'=' * 70}")
    print(f"  {label}  ({idx}/{total})  --->  SEARCHING")
    print(f"{'=' * 70}")
    print(f"  Start  (hex)     : {start:064x}")
    print(f"  End    (hex)     : {end:064x}")
    print(f"  Percent          : {PERCENT}")
    print(f"  Central key (hex): {central_key:064x}")
    print(f"  Central page     : {central_page}")
    print(f"  Pages to scan    : {first_page} --> {last_page}")
    print(f"  Total addresses  : {last_offset - first_offset + 1}")
    print(f"  Prefix length    : {PREFIX_LEN}")
    print(f"{'=' * 70}\n")

    total_addrs = last_offset - first_offset + 1
    prefix_matches = 0

    prefix_fh = open(PREFIX_FILE, "a", encoding="utf-8")
    try:
        for i, off in enumerate(range(first_offset, last_offset + 1), start=1):
            key = start + off
            try:
                addr = priv_to_address_compressed(key)
            except Exception:
                continue

            # ---- FULL MATCH: stop immediately ----
            if addr in full_targets:
                print(f"  [{i}/{total_addrs}] {addr}")

                with open(FOUND_FILE, "a", encoding="utf-8") as ff:
                    ff.write(f"Puzzle          : {puzzle_num}\n")
                    ff.write(f"Private key dec : {key}\n")
                    ff.write(f"Private key hex : {key:064x}\n")
                    ff.write(f"Address         : {addr}\n")
                    ff.write("-" * 40 + "\n")
                    ff.flush()
                    os.fsync(ff.fileno())

                prefix_fh.write(f"{key} {key:064x} {addr}  <-- FULL MATCH\n")
                prefix_fh.flush()
                os.fsync(prefix_fh.fileno())

                print(f"\n{'*' * 70}")
                print(f"*** FULL MATCH FOUND ***")
                print(f"  Puzzle          : {puzzle_num}")
                print(f"  Private key dec : {key}")
                print(f"  Private key hex : {key:064x}")
                print(f"  Address         : {addr}")
                print(f"{'*' * 70}\n")
                return True, key, addr

            # ---- PREFIX MATCH: save and continue ----
            if addr[:PREFIX_LEN] in prefixes:
                prefix_matches += 1
                prefix_fh.write(f"{key} {key:064x} {addr}\n")
                prefix_fh.flush()
                os.fsync(prefix_fh.fileno())

                print(f"  [{i}/{total_addrs}] {addr}")
                print(f"  >>> [PREFIX MATCH #{prefix_matches} | {PREFIX_LEN} chars] SAVED to {PREFIX_FILE} <<<")
            else:
                print(f"  [{i}/{total_addrs}] {addr}")

            if i % 5000 == 0:
                print(f"  --- progress {i}/{total_addrs} | prefix matches: {prefix_matches} ---")
    finally:
        prefix_fh.close()

    print(f"\n  {label} DONE  |  prefix matches: {prefix_matches}")
    return False, None, None


def main():
    print("=== Bitcoin Puzzle Scanner (Compressed) ===\n")

    if not os.path.exists("range.txt"):
        print("ERROR: range.txt not found.")
        sys.exit(1)
    if not os.path.exists("address.txt"):
        print("ERROR: address.txt not found.")
        sys.exit(1)

    ranges = load_ranges("range.txt")
    full_targets, prefixes = load_addresses("address.txt")

    if not ranges:
        print("ERROR: no valid ranges found in range.txt")
        sys.exit(1)

    print(f"  Loaded {len(ranges)} range(s)")
    print(f"  Loaded {len(full_targets)} target address(es)")
    print(f"  Percent       : {PERCENT}")
    print(f"  Prefix length : {PREFIX_LEN}")
    print(f"  Prefixes      : {prefixes}\n")

    for fn in (PREFIX_FILE, FOUND_FILE):
        if os.path.exists(fn):
            os.remove(fn)

    total = len(ranges)

    for idx, (puzzle_num, start, end) in enumerate(ranges, start=1):
        found, key, addr = scan_range(puzzle_num, start, end, full_targets, prefixes, idx, total)
        if found:
            print("=" * 70)
            print("  SCAN STOPPED - KEY FOUND")
            print("=" * 70)
            print(f"  Puzzle          : {puzzle_num}")
            print(f"  Private key dec : {key}")
            print(f"  Private key hex : {key:064x}")
            print(f"  Address         : {addr}")
            print("=" * 70)
            print(f"  Full match saved to : {FOUND_FILE}")
            print(f"  Also recorded in    : {PREFIX_FILE}")
            return

    print("\n" + "=" * 70)
    print("  ALL RANGES SCANNED - NO FULL MATCH FOUND")
    print("=" * 70)
    if os.path.exists(PREFIX_FILE):
        with open(PREFIX_FILE, "r") as f:
            n = sum(1 for _ in f)
        print(f"  Total prefix matches saved: {n}  ({PREFIX_FILE})")


if __name__ == "__main__":
    main()
