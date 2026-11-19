'''
17 May 2026

Authors:
- Ayush Rakwal
- Baleshwar Singh
- Dipankar Dutta

About:
- This program implements the decryption algorithm for the LWE-based encryption scheme.
- It reads the public and private keys, processes the ciphertext from the binary file, and reconstructs the original message.
- The decryption process involves computing the inner product of the secret key with the ciphertext component, adjusting for the modulus, and recovering the original chunks.

Usage:
- String decryption: sage Decrypt.py 1 <publicfile> <privatefile> <cipherfile>
- File decryption:   sage Decrypt.py 2 <publicfile> <privatefile> <cipherfile>

Sample Input/Output Sets
Input 1.1:
Execution: sage Decrypt.py 1 public.txt private.txt cipher_string.txt

Output:
Decrypted 28/28 bytes (100%)...
Decrypted message: Hello World !!
Time taken to dencrypt: 0.05 seconds

Input 1.2:
Execution: sage Decrypt.py 2 public.txt private.txt cipher_file.txt 

Output:
Decrypted 2215244/2215244 bytes (100%)...
Decrypted successfully: recovered_transformer_paper.pdf
Time taken to dencrypt: 2.31 minutes

'''



from sage.all import *
import pickle
import json
import sys
import os
import time



def read_public(filename):

    with open(filename, 'r') as f:
        content = f.read()

    params = {}
    for line in content.splitlines():
        line = line.strip()
        if ':' in line and not line.startswith('[') and not line.startswith('('):
            key, _, val = line.partition(':')
            key = key.strip()
            val = val.strip()
            if key in ('modulus', 'mBit'):
                params[key] = val

    q    = Integer(params['modulus'])
    mBit = Integer(params.get('mBit', 8))

    return q, mBit



def read_private(filename):

    with open(filename, 'r') as f:
        raw_lines = f.readlines()

    content = ' '.join(line.strip() for line in raw_lines)

    import re
    match = re.search(r's:\s*\(([^)]+)\)', content)
    if match:
        val_str = match.group(1)
        return vector(ZZ, [int(x.strip()) for x in val_str.split(',') if x.strip()])

    raise ValueError("Private key 's' not found in file.")



def decrypt_value(q, mBit, s, c1, c2):

    t = int(s.dot_product(c1)) % q

    x = (int(c2) % q) - t

    x_pos = int(x) % int(q)

    step = int(q) // int(2**mBit)

    mu = ((x_pos + step // 2) // step) % int(2**mBit)

    return mu



def stream_ciphers(f):

    while True:

        try:
            yield pickle.load(f)

        except EOFError:
            break


def is_json_cipher(filename):
    """Detect NDJSON ciphertext independently of its output filename."""
    with open(filename, 'rb') as cipher_f:
        return cipher_f.read(4096).lstrip().startswith(b'{')


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
    """
    Little-endian packing of bytes_per_chunk bytes into one integer.
    """
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

def decrypt_string(public_file, private_file, cipher_file):

    q, mBit = read_public(public_file)
    s        = read_private(private_file)
    params   = get_chunk_params(mBit)

    # JSON encryption currently uses .txt output names, so inspect content.
    is_json = is_json_cipher(cipher_file)

    if is_json:
        with open(cipher_file, 'r') as cipher_f:
            header     = json.loads(cipher_f.readline())
            total_size = header["size"]

            if params["mode"] == "sub_byte":
                chunks_per_byte = params["chunks_per_byte"]
                chunk_buf = []
                recovered_bytes = bytearray()

                for line in cipher_f:
                    item = json.loads(line)
                    c1 = vector(ZZ, item["c1"])
                    c2 = Integer(item["c2"])
                    mu = decrypt_value(q, mBit, s, c1, c2)
                    chunk_buf.append(mu)

                    if len(chunk_buf) == chunks_per_byte:
                        byte_val = 0
                        for i, ch in enumerate(chunk_buf):
                            byte_val |= ch << (i * mBit)
                        if len(recovered_bytes) < total_size:
                            recovered_bytes.append(byte_val & 0xFF)
                            pct = len(recovered_bytes) * 100 // total_size
                            print(f"Decrypted {len(recovered_bytes)}/{total_size} bytes ({pct}%)...", flush=True, end='\r')
                        chunk_buf = []

            else:
                bpc = params["bytes_per_chunk"]
                recovered_bytes = bytearray()

                for line in cipher_f:
                    item = json.loads(line)
                    c1  = vector(ZZ, item["c1"])
                    c2  = Integer(item["c2"])
                    mu  = decrypt_value(q, mBit, s, c1, c2)
                    block = unpack_multi_byte(mu, bpc)

                    remaining = total_size - len(recovered_bytes)
                    recovered_bytes.extend(block[:remaining])
                    pct = len(recovered_bytes) * 100 // total_size
                    print(f"Decrypted {len(recovered_bytes)}/{total_size} bytes ({pct}%)...", flush=True, end='\r')

    else:
        with open(cipher_file, "rb") as cipher_f:
            header     = pickle.load(cipher_f)
            total_size = header["size"]   

            if params["mode"] == "sub_byte":
                chunks_per_byte = params["chunks_per_byte"]
                chunk_buf = []
                recovered_bytes = bytearray()

                for item in stream_ciphers(cipher_f):
                    c1 = vector(ZZ, item["c1"])
                    c2 = Integer(item["c2"])
                    mu = decrypt_value(q, mBit, s, c1, c2)
                    chunk_buf.append(mu)

                    if len(chunk_buf) == chunks_per_byte:
                        byte_val = 0
                        for i, ch in enumerate(chunk_buf):
                            byte_val |= ch << (i * mBit)
                        if len(recovered_bytes) < total_size:
                            recovered_bytes.append(byte_val & 0xFF)
                            pct = len(recovered_bytes) * 100 // total_size
                            print(f"Decrypted {len(recovered_bytes)}/{total_size} bytes ({pct}%)...", flush=True, end='\r')
                        chunk_buf = []

            else:
                bpc = params["bytes_per_chunk"]
                recovered_bytes = bytearray()

                for item in stream_ciphers(cipher_f):
                    c1  = vector(ZZ, item["c1"])
                    c2  = Integer(item["c2"])
                    mu  = decrypt_value(q, mBit, s, c1, c2)
                    block = unpack_multi_byte(mu, bpc)

                    remaining = total_size - len(recovered_bytes)
                    recovered_bytes.extend(block[:remaining])
                    pct = len(recovered_bytes) * 100 // total_size
                    print(f"Decrypted {len(recovered_bytes)}/{total_size} bytes ({pct}%)...", flush=True, end='\r')
    
    print()
    message = recovered_bytes.decode('utf-8')
    print(f"Decrypted message: {message}")


def decrypt_file(public_file, private_file, cipher_file):

    q, mBit = read_public(public_file)
    s        = read_private(private_file)
    params   = get_chunk_params(mBit)

    # JSON encryption currently uses .txt output names, so inspect content.
    is_json = is_json_cipher(cipher_file)

    if is_json:
        with open(cipher_file, 'r') as cipher_f:
            header     = json.loads(cipher_f.readline())
            total_size = header["size"]
            orig_name  = os.path.basename(header["filename"])
            out_name   = "recovered_" + orig_name
            recovered  = 0

            with open(out_name, "wb") as out_f:

                if params["mode"] == "sub_byte":
                    chunks_per_byte = params["chunks_per_byte"]
                    chunk_buf = []
                    for line in cipher_f:
                        item = json.loads(line)
                        c1 = vector(ZZ, item["c1"])
                        c2 = Integer(item["c2"])
                        mu = decrypt_value(q, mBit, s, c1, c2)
                        chunk_buf.append(mu)

                        if len(chunk_buf) == chunks_per_byte:
                            byte_val = 0
                            for i, ch in enumerate(chunk_buf):
                                byte_val |= ch << (i * mBit)
                            if recovered < total_size:
                                out_f.write(bytes([byte_val & 0xFF]))
                                recovered += 1
                                
                                pct = recovered * 100 // total_size
                                print(f"Decrypted {recovered}/{total_size} bytes ({pct}%)...", flush=True, end='\r')
                            chunk_buf = []

                else:
                    bpc = params["bytes_per_chunk"]
                    for line in cipher_f:
                        item = json.loads(line)
                        c1    = vector(ZZ, item["c1"])
                        c2    = Integer(item["c2"])
                        mu    = decrypt_value(q, mBit, s, c1, c2)
                        block = unpack_multi_byte(mu, bpc)

                        remaining = total_size - recovered
                        out_f.write(block[:remaining])
                        recovered += min(bpc, remaining)
                        
                        pct = recovered * 100 // total_size
                    print(f"Decrypted {recovered}/{total_size} bytes ({pct}%)...", flush=True, end='\r')

        #print(f"\nDecrypted successfully: {out_name}")

    else:
        with open(cipher_file, "rb") as cipher_f:
            header     = pickle.load(cipher_f)
            total_size = header["size"]
            orig_name  = os.path.basename(header["filename"])
            out_name   = "recovered_" + orig_name
            recovered  = 0

            with open(out_name, "wb") as out_f:

                if params["mode"] == "sub_byte":
                    chunks_per_byte = params["chunks_per_byte"]
                    chunk_buf = []
                    for item in stream_ciphers(cipher_f):
                        c1 = vector(ZZ, item["c1"])
                        c2 = Integer(item["c2"])
                        mu = decrypt_value(q, mBit, s, c1, c2)
                        chunk_buf.append(mu)

                        if len(chunk_buf) == chunks_per_byte:
                            byte_val = 0
                            for i, ch in enumerate(chunk_buf):
                                byte_val |= ch << (i * mBit)
                            if recovered < total_size:
                                out_f.write(bytes([byte_val & 0xFF]))
                                recovered += 1
                                
                                pct = recovered * 100 // total_size
                                print(f"Decrypted {recovered}/{total_size} bytes ({pct}%)...", flush=True, end='\r')
                            chunk_buf = []

                else:
                    bpc = params["bytes_per_chunk"]
                    for item in stream_ciphers(cipher_f):
                        c1    = vector(ZZ, item["c1"])
                        c2    = Integer(item["c2"])
                        mu    = decrypt_value(q, mBit, s, c1, c2)
                        block = unpack_multi_byte(mu, bpc)

                        remaining = total_size - recovered
                        out_f.write(block[:remaining])
                        recovered += min(bpc, remaining)
                        
                        pct = recovered * 100 // total_size
                    print(f"Decrypted {recovered}/{total_size} bytes ({pct}%)...", flush=True, end='\r')


    print(f"\nDecrypted successfully: {out_name}")


def time_taken(duration):

    if duration < 60:
        print(f"Time taken to decrypt: {duration:.2f} seconds")

    elif duration < 3600:
        print(f"Time taken to decrypt: {duration / 60:.2f} minutes")

    else:
        print(f"Time taken to decrypt: {duration / 3600:.2f} hours")

def main():

    if len(sys.argv) != 5:

        print("\nUsage:")
        print("  String: sage Decrypt.py 1 <publicfile> <privatefile> <cipherfile>")
        print("  File:   sage Decrypt.py 2 <publicfile> <privatefile> <cipherfile>")

        return

    mode = int(sys.argv[1])

    public_file = sys.argv[2]

    private_file = sys.argv[3]

    cipher_file = sys.argv[4]

    try:

        start_time = time.time()

        if mode == 1:

            decrypt_string(public_file, private_file, cipher_file)

        elif mode == 2:

            decrypt_file(public_file, private_file, cipher_file)

        else:
            raise ValueError("Invalid mode")

        duration = time.time() - start_time

        time_taken(duration)

    except Exception as e:
        print("Error:", e)


if __name__ == '__main__':
    main()
