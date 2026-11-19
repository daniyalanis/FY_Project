'''
17 May 2026

Authors:
- Ayush Rakwal
- Baleshwar Singh
- Dipankar Dutta

About:
- This program implements the encryption algorithm for the LWE-based encryption 
scheme.
- It takes a message (string or file) and encrypts it using the public key parameters. 
- The encryption process involves encoding the message into chunks, generating r
andom vectors, and computing the ciphertext components based on the LWE scheme. 
- The resulting ciphertext can be saved as NDJSON (newline-delimited JSON) in txt format for portability.

Usage: 
- String encryption: sage Encrypt.py 1 <publicfile> '<message>'
- File encryption:   sage Encrypt.py 2 <publicfile> <filename> 


Sample Input/Output Sets

Input 1.1:
Execution: sage Encrypt.py 1 public.txt 'Hello, World !!'

Output:
Encrypted chunk 28/28 (100%)...
Encryption done. 14 bytes: cipher_string.txt
Time taken to encrypt: 0.06 seconds

Input 1.2 :
Execution: sage Encrypt.py 2 public.txt transformer_paper.pdf
Output:
Encrypted 2215244/2215244 bytes (100%)...
Encryption done. 2215244 bytes.
Time taken to encrypt: 2.65 minutes
'''


from sage.all import *
import random
import pickle
import json
import sys
import time
import os

CHUNK_SIZE= 4096


def encrypt_value(mu, A, b, F, m, step):

    r_mod = vector(F, [randint(0, 1) for _ in range(m)])

    c1 = r_mod * A

    encoded_mu = mu * step

    c2 = r_mod * b + F(encoded_mu)

    return {
        'c1': [int(x) for x in c1],
        'c2': int(c2)
    }


def _join_multiline(lines, start_idx, open_ch, close_ch):
    """
    Starting at start_idx, joins continuation lines until the closing
    bracket/paren is found. Returns (joined_string, next_line_index).
    """
    buf = lines[start_idx]
    i = start_idx
    while close_ch not in buf and i + 1 < len(lines):
        i += 1
        buf += ' ' + lines[i].strip()
    return buf, i + 1


def load_public(public_filename):

    with open(public_filename, 'r') as f:
        raw_lines = f.read().splitlines()

    params = {}
    A_rows = []
    reading_A = False
    reading_b = False
    i = 0

    while i < len(raw_lines):
        line = raw_lines[i].strip()

        if not line:
            reading_A = False
            reading_b = False
            i += 1
            continue

        if line == 'A:':
            reading_A = True
            i += 1
            continue

        if line == 'b:' or (line.startswith('b:') and '(' in line):
            reading_A = False
            reading_b = True
            if '(' in line:
                open_idx = line.index('(')
                vec_part = line[open_idx:]
                if ')' in vec_part:
                    b_str = vec_part.strip().strip('()')
                    params['b'] = [int(x.strip()) for x in b_str.split(',') if x.strip()]
                    reading_b = False
                    i += 1
                else:
                    full_vec, i = _join_multiline(raw_lines, i, '(', ')')
                    b_str = full_vec.strip().strip('()')
                    params['b'] = [int(x.strip()) for x in b_str.split(',') if x.strip()]
                    reading_b = False
                continue
            i += 1
            continue

        if reading_A and line.startswith('['):
            full_row, i = _join_multiline(raw_lines, i, '[', ']')
            row_str = full_row.strip().strip('[]')
            A_rows.append([int(x) for x in row_str.split()])
            continue

        if reading_b and line.startswith('('):
            full_vec, i = _join_multiline(raw_lines, i, '(', ')')
            b_str = full_vec.strip().strip('()')
            params['b'] = [int(x.strip()) for x in b_str.split(',') if x.strip()]
            reading_b = False
            continue

        if ':' in line and not line.startswith('[') and not line.startswith('('):
            key, _, val = line.partition(':')
            params[key.strip()] = val.strip()

        i += 1

    q    = int(params['modulus'])
    mBit = int(params.get('mBit', 8))
    F    = GF(q)
    A    = Matrix(F, A_rows)
    b    = vector(F, params['b'])
    m    = A.nrows()
    step = q // 2**mBit

    return q, mBit, F, A, b, m, step

def get_chunk_params(mBit):
    """
    Returns (chunks_per_byte, bits_per_chunk, mask) for mBit <= 8,
    or      (bytes_per_chunk, bits_per_chunk, mask) for mBit > 8.

    """
    mask = (1 << mBit) - 1

    if mBit <= 8:
        # sub-byte: multiple ciphertexts per byte
        chunks_per_byte = 8 // mBit     
        return {
            "mode":            "sub_byte",
            "chunks_per_byte": chunks_per_byte,
            "mask":            mask
        }
    else:
        # multi-byte: multiple bytes per ciphertext
        bytes_per_chunk = mBit // 8             
        return {
            "mode":            "multi_byte",
            "bytes_per_chunk": bytes_per_chunk,
            "mask":            mask
        }


def pack_sub_byte(data_bytes, mBit, mask):
    chunks_per_byte = 8 // mBit
    for byte in data_bytes:
        for i in range(chunks_per_byte):
            yield (byte >> (i * mBit)) & mask


def unpack_sub_byte(chunks, mBit, num_bytes):
    """
    Reconstructs bytes from a flat list of chunks.
    """
    chunks_per_byte = 8 // mBit
    result = bytearray()
    byte = 0
    bit_pos = 0
    for chunk in chunks:
        byte |= (chunk << bit_pos)
        bit_pos += mBit
        if bit_pos == 8:
            result.append(byte & 0xFF)
            byte = 0
            bit_pos = 0
            if len(result) == num_bytes:
                break
    return bytes(result)


def pack_multi_byte(block, mBit):
    value = 0
    for i, byte in enumerate(block):
        value |= byte << (8 * i)
    return value


def unpack_multi_byte(value, bytes_per_chunk):
    result = bytearray()
    for _ in range(bytes_per_chunk):
        result.append(value & 0xFF)
        value >>= 8
    return bytes(result)


def LWE_Encrypt_String(public_filename, message, out_format='pickle'):

    q, mBit, F, A, b, m, step = load_public(public_filename)
    params = get_chunk_params(mBit)

    # Encode message to bytes (UTF-8)
    data_bytes = message.encode('utf-8')
    total_bytes = len(data_bytes)

    header = {
        "type":  "string",
        "size":  total_bytes,
        "mBit":  mBit
    }

    if out_format == 'json':
        out_name = 'cipher_string.txt'
        with open(out_name, 'w') as out_f:
            out_f.write(json.dumps(header) + '\n')

            if params["mode"] == "sub_byte":
                mus = list(pack_sub_byte(data_bytes, mBit, params["mask"]))
                for i, mu in enumerate(mus):
                    cipher = encrypt_value(mu, A, b, F, m, step)
                    out_f.write(json.dumps(cipher) + '\n')
                    pct = (i + 1) * 100 // len(mus)
                    print(f"Encrypted chunk {i+1}/{len(mus)} ({pct})%...", flush=True, end='\r')

            else:
                bpc = params["bytes_per_chunk"]
                blocks = []
                for i in range(0, len(data_bytes), bpc):
                    block = data_bytes[i:i + bpc]
                    if len(block) < bpc:
                        block += bytes(bpc - len(block))   
                    blocks.append(block)

                for i, block in enumerate(blocks):
                    mu = pack_multi_byte(block, mBit)
                    cipher = encrypt_value(mu, A, b, F, m, step)
                    out_f.write(json.dumps(cipher) + '\n')
                    pct = (i + 1) * 100 // len(blocks)
                    print(f"Encrypted chunk {i+1}/{len(blocks)} ({pct}%)...", flush=True, end='\r')

        print(f"\nEncryption done. {total_bytes} bytes: {out_name}")
        return out_name

    # default: pickle
    out_name = 'cipher_string.bin'
    with open(out_name, 'wb') as out_f:
        pickle.dump(header, out_f)

        if params["mode"] == "sub_byte":
            mus = list(pack_sub_byte(data_bytes, mBit, params["mask"]))
            for i, mu in enumerate(mus):
                cipher = encrypt_value(mu, A, b, F, m, step)
                pickle.dump(cipher, out_f)
                pct = (i + 1) * 100 // len(mus)
                print(f"Encrypted chunk {i+1}/{len(mus)} ({pct}%)...", flush=True, end='\r')

        else:
            bpc = params["bytes_per_chunk"]
            blocks = []
            for i in range(0, len(data_bytes), bpc):
                block = data_bytes[i:i + bpc]
                if len(block) < bpc:
                    block += bytes(bpc - len(block))   
                blocks.append(block)

            for i, block in enumerate(blocks):
                mu = pack_multi_byte(block, mBit)
                cipher = encrypt_value(mu, A, b, F, m, step)
                pickle.dump(cipher, out_f)
                pct = (i + 1) * 100 // len(blocks)
                print(f"Encrypted chunk {i+1}/{len(blocks)} ({pct}%)...", flush=True, end='\r')

    print(f"\nEncryption done. {total_bytes} bytes: {out_name}")
    return out_name


def LWE_Encrypt_File(public_filename, filename, out_format='pickle'):

    q, mBit, F, A, b, m, step = load_public(public_filename)
    params   = get_chunk_params(mBit)
    file_size = os.path.getsize(filename)

    header = {
        "type":  "file",
        "filename": filename,
        "size":  file_size,
        "mBit":  mBit
    }

    processed = 0

    if out_format == 'json':
        out_name = 'cipher_file.txt'
        with open(out_name, 'w') as out_f:
            out_f.write(json.dumps(header) + '\n')

            with open(filename, 'rb') as in_f:
                while True:
                    chunk = in_f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    if params["mode"] == "sub_byte":
                        for mu in pack_sub_byte(chunk, mBit, params["mask"]):
                            cipher = encrypt_value(mu, A, b, F, m, step)
                            out_f.write(json.dumps(cipher) + '\n')

                    else:
                        bpc = params["bytes_per_chunk"]
                        for i in range(0, len(chunk), bpc):
                            block = chunk[i:i + bpc]
                            if len(block) < bpc:
                                block += bytes(bpc - len(block))  
                            mu = pack_multi_byte(block, mBit)
                            cipher = encrypt_value(mu, A, b, F, m, step)
                            out_f.write(json.dumps(cipher) + '\n')

                    processed += len(chunk)
                    pct = processed * 100 // file_size
                    print(f"Encrypted {processed}/{file_size} bytes ({pct}%)...", flush=True, end='\r')

        print(f"\nEncryption done. {file_size} bytes: {out_name}")
        return out_name

    out_name = 'cipher_file.bin'

    with open(out_name, 'wb') as out_f:
        pickle.dump(header, out_f)

        with open(filename, 'rb') as in_f:
            while True:
                chunk = in_f.read(CHUNK_SIZE)
                if not chunk:
                    break

                if params["mode"] == "sub_byte":
                    for mu in pack_sub_byte(chunk, mBit, params["mask"]):
                        cipher = encrypt_value(mu, A, b, F, m, step)
                        pickle.dump(cipher, out_f)

                else:
                    bpc = params["bytes_per_chunk"]
                    for i in range(0, len(chunk), bpc):
                        block = chunk[i:i + bpc]
                        if len(block) < bpc:
                            block += bytes(bpc - len(block))  
                        mu = pack_multi_byte(block, mBit)
                        cipher = encrypt_value(mu, A, b, F, m, step)
                        pickle.dump(cipher, out_f)

                processed += len(chunk)
                pct = processed * 100 // file_size
                print(f"Encrypted {processed}/{file_size} bytes ({pct}%)...", flush=True, end='\r')

    print(f"\nEncryption done. {file_size} bytes: {out_name}")
    return out_name


def time_taken(duration):

    if duration < 60:
        print(f"Time taken to encrypt: {duration:.2f} seconds")

    elif duration < 3600:
        print(f"Time taken to encrypt: {duration / 60:.2f} minutes")

    else:
        print(f"Time taken to encrypt: {duration / 3600:.2f} hours")

def main():

    if len(sys.argv) < 4:

        print("\nUsage:")
        print("  String: sage Encrypt.py 1 <publicfile> <message>")
        print("  File:   sage Encrypt.py 2 <publicfile> <filename>")

        sys.exit(1)

    mode = int(sys.argv[1])

    public_filename = sys.argv[2]

    out_format = 'json'
    '''
    if len(sys.argv) >= 5:
        out_format = sys.argv[4].lower()
        if out_format not in ('pickle', 'json'):
            print("Unknown format; valid: pickle, json")
            return
    '''
    try:

        start_time = time.time()

        if mode == 1:

            out_name = LWE_Encrypt_String(public_filename, sys.argv[3], out_format)

        elif mode == 2:

            out_name = LWE_Encrypt_File(public_filename, sys.argv[3], out_format)

        else:
            raise ValueError("Invalid mode")

        duration = time.time() - start_time

        time_taken(duration)

    except Exception as e:
        print("Error:", e)


if __name__ == '__main__':
    main()
