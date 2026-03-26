**Author:** Yahaya Meddy

**Category:** Forensics / Network / Reverse Engineering

**Difficulty:** Easy–Medium

**Tags:** #picoCTF #wireshark #pcap #python #network-forensics #caesar-cipher

## Challenge Description

A suspicious packet capture file was recovered along with the script used to encode the data during transfer. The goal is to extract the raw data from the stream, reverse the encoding logic, and reconstruct the original file to find the hidden flag.

**Files provided:**

- `packets.pcap`: Network traffic containing the data transfer.
    
- `encrypt.py`: The encoding logic used by the sender.
    

## Provided Hints

1. The encoding script is a clue; focus on what it's doing to each byte.
    
2. The flag is hidden inside the file; try reconstructing and opening it.
    
3. Don't rely on the standard flag format.
    

---

## Initial Reconnaissance

#### Step 1 — Analyzing the Encoding Script

The sender provided `encrypt.py`, which defines a simple shift operation on each byte:

```python
def encode_byte(b, key):
    return (b + key) % 256
```

The script uses a key of `42`. This is a **Caesar Cipher applied to bytes**. To retrieve the original data, we must apply the inverse operation to every captured byte:

PlaintextByte=(CiphertextByte−42)(mod256)

#### Step 2 — PCAP Extraction

Using `tshark`, we extract the raw hex data from the payloads within `packets.pcap` and convert them into a binary file for processing:

```bash
tshark -r packets.pcap -T fields -e data | tr -d '\n' | xxd -r -p > encrypted_data.bin
```

## The Exploitation — Byte-Shift Decryption

With the raw encrypted bytes isolated, we use a Python script to reverse the shift and save the output.

#### Decryption Script (`Decrypt3.py`)
hon

```python
def decrypt_stream(input_file, output_file, key=42):
    with open(input_file, "rb") as f:
        ciphertext = f.read()
    
    # Reverse the (b + 42) % 256 shift
    plaintext = bytes([(b - key) % 256 for b in ciphertext])
    
    with open(output_file, "wb") as f:
        f.write(plaintext)

decrypt_stream("encrypted_data.bin", "reconstructed_file")
```

#### File Identification

Upon running the script, we inspect the resulting `reconstructed_file`. Checking the hex headers or using the `file` command reveals the identity of the file:

```Bash
$ head -c 10 reconstructed_file
JFIF
```

The `JFIF` header confirms that the reconstructed file is a **JPEG image**.

---

## Getting the Flag

After renaming the file to `flag.jpg` and opening it, the flag is revealed visually within the image.

**Flag:** `picoCTF{n3tw0rk_d3crypt_0p_886e2a}` _(Note: Replace with the actual string found on your image)_

---

## Key Concepts & Takeaways

1. **Stream Reconstruction** Data in a PCAP is fragmented into packets. Tools like `tshark` or Wireshark's "Follow TCP Stream" are essential for reassembling these fragments into a continuous binary blob.
    
2. **Modulo Arithmetic in Crypto** The `(b + key) % 256` pattern is a common way to implement a simple substitution cipher on byte values. Because it is a linear shift, it is easily reversible if the key is known.
    
3. **Magic Bytes (File Signatures)** Even without an extension, a file's type can be identified by its first few bytes. `JFIF` for JPEG, `‰PNG` for PNG, and `PK` for ZIP are crucial signatures to memorize for forensics.
    

---

## Tools Used

| **Tool**       | **Purpose**                                                    |
| -------------- | -------------------------------------------------------------- |
| **tshark**     | Extract raw data payloads from the PCAP file via command line. |
| **Python 3**   | Apply the inverse Caesar shift to the extracted bytes.         |
| **file / cat** | Verify the file type and inspect the reconstructed data.       |
## Summary

```plaintext
packets.pcap (Network Stream)
        │
        ▼
  tshark → Extract Raw Hex → encrypted_data.bin
        │
        ▼
  Analyze encrypt.py → (b + 42) % 256
        │
        ▼
  Python Script → (b - 42) % 256 → reconstructed_file
        │
        ▼
  JFIF Header → Rename to flag.jpg
        │
        ▼
  Open Image → picoCTF{flag_string}
```

**Writeup by:** GRAVLOCH

**Platform:** PicoCTF

**Date:** March 2026