#!/usr/bin/env python3

import sys
import struct
import hashlib
import zipfile
import json
import base64


def base26(data: bytes) -> str:

    result = []

    for byte in data:
        result.append(chr(ord('a') + (byte >> 4)))
        result.append(chr(ord('a') + (byte & 0x0f)))

    return ''.join(result)


def id_from_pubkey(pubkey_bytes: bytes) -> str:

    digest = hashlib.sha256(pubkey_bytes).digest()

    return base26(digest[:16])


def extract_crx3(data: bytes):

    if data[:4] != b'Cr24':
        raise ValueError("Not a CRX3 file (bad magic)")

    version = struct.unpack_from('<I', data, 4)[0]
    if version != 3:
        raise ValueError(f"Unsupported CRX version: {version}")

    header_size = struct.unpack_from('<I', data, 8)[0]
    header_bytes = data[12: 12 + header_size]
    zip_start    = 12 + header_size

    return header_bytes, zip_start


def find_public_key_in_proto(header_bytes: bytes):

    keys = []

    def read_varint(buf, pos):

        result, shift = 0, 0

        while pos < len(buf):
            b = buf[pos]; pos += 1
            result |= (b & 0x7f) << shift

            if not (b & 0x80):
                break
            shift += 7

        return result, pos

    def read_len_delimited(buf, pos):

        length, pos = read_varint(buf, pos)
        return buf[pos: pos + length], pos + length

    def parse_proof(buf):

        pos = 0
        pub = None

        while pos < len(buf):
            tag_raw, pos = read_varint(buf, pos)
            field = tag_raw >> 3
            wtype = tag_raw & 0x7

            if wtype == 2:
                val, pos = read_len_delimited(buf, pos)
                if field == 1:
                    pub = val
                # field 2 = signature, skip
            elif wtype == 0:
                _, pos = read_varint(buf, pos)
           
            else:
                break

        return pub

    pos = 0

    while pos < len(header_bytes):
        try:
            tag_raw, pos = read_varint(header_bytes, pos)
        except Exception:
            break
        field = tag_raw >> 3
        wtype = tag_raw & 0x7

        if wtype == 2:
            val, pos = read_len_delimited(header_bytes, pos)
            if field in (2, 3):   # sha256_with_rsa or sha256_with_ecdsa
                pub = parse_proof(val)
                if pub:
                    keys.append(pub)

        elif wtype == 0:
            _, pos = read_varint(header_bytes, pos)

        else:
            break

    return keys


def extract_key_from_manifest(zip_data: bytes):

    try:
        import io
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            manifest = json.loads(z.read('manifest.json'))
            key_b64 = manifest.get('key')

            if key_b64:
                return base64.b64decode(key_b64)

    except Exception:
        pass

    return None


def main():
    if len(sys.argv) < 2:
        print("usage: python get_crx_id.py <file.crx>")
        sys.exit(1)

    path = sys.argv[1]

    with open(path, 'rb') as f:
        data = f.read()

    try:
        header_bytes, zip_start = extract_crx3(data)

    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    zip_data = data[zip_start:]

    keys = find_public_key_in_proto(header_bytes)

    if keys:

        print(f"[+] found {len(keys)} key(s) in CRX3 header\n")

        for i, pub in enumerate(keys):
            ext_id = id_from_pubkey(pub)
            pub_b64 = base64.b64encode(pub).decode()
            print(f"  key {i+1}")
            print(f"    extension ID : {ext_id}")
            print(f"    public key   : {pub_b64[:64]}...")
            print()
    else:

        print("[-] no key in CRX3 header, trying manifest.json key field...")
        pub = extract_key_from_manifest(zip_data)

        if pub:
            ext_id = id_from_pubkey(pub)
            pub_b64 = base64.b64encode(pub).decode()
            print(f"\n[+] key from manifest")
            print(f"    extension ID : {ext_id}")
            print(f"    public key   : {pub_b64[:64]}...")

        else:
            print("[!] could not extract public key from header or manifest")
            sys.exit(1)


if __name__ == "__main__":
    main()