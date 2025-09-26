#!/usr/bin/env python3
import argparse
from Crypto.Cipher import ARC4

def encrypt_file(input_file, output_file, key):
    """Encrypt input_file with RC4 and save as output_file."""
    with open(input_file, "rb") as f:
        data = f.read()

    cipher = ARC4.new(key.encode("utf-8"))
    encrypted = cipher.encrypt(data)

    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"[+] Encrypted {input_file} -> {output_file} ({len(data)} bytes)")

def main():
    parser = argparse.ArgumentParser(description="RC4 Encrypt a DLL")
    parser.add_argument("-i", required=True, help="Path to the input DLL")
    parser.add_argument("-o", required=True, help="Path for the encrypted output")
    parser.add_argument("-k", required=True, help="RC4 key for encryption")
    args = parser.parse_args()
    encrypt_file(args.i, args.o, args.k)

if __name__ == "__main__":
    main()
