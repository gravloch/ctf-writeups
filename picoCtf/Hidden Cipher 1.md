
> **Author:** Yahaya Meddy 
> **Category:** Reverse Engineering 
> **Difficulty:** Easy–Medium 
> **Tags:** #reverse-engineering #xor #cryptography #upx #known-plaintext-attack

---

## Challenge Description

> _The flag is right in front of you; just slightly encrypted. All you have to do is figure out the cipher and the key._

We are given a binary (`hiddencipher`) and a netcat endpoint:

```
nc candy-mountain.picoctf.net 62632
```

---

## Provided Hints

1. _The binary can be unpacked using a tool that's often pre-installed on Linux._
2. _The program hides a secret. Look at how it's defined and used._
3. _Think XOR. What happens when you XOR something twice with the same key?_

These hints directly telegraph the solution path: **unpack → find the XOR key → decrypt**.

---

## Initial Reconnaissance

### Step 1 — Identifying the Binary

Running `file` on the binary immediately reveals it is packed:

```bash
$ file hiddencipher
hiddencipher: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
statically linked, no section header
```

The absence of section headers is a strong indicator of a packer. Confirming with `strings`:

```bash
$ strings hiddencipher | head -5
UPX!
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
```

**UPX** (Ultimate Packer for eXecutables) is confirmed. This is the packer referenced in Hint 1.

---

### Step 2 — Inspecting the Archive Contents

The zip also included a `flag.txt`:

```bash
$ cat flag.txt
picoCTF{fake_flag}
```

This is a **placeholder flag** — critically important for what comes next.

---

### Step 3 — Unpacking with UPX

```bash
$ upx -d hiddencipher -o hiddencipher_unpacked
```

This decompresses the binary and restores a proper ELF with section headers, making it fully amenable to static analysis in tools like Ghidra, IDA Free, or Radare2.

> **Note:** If UPX is not installed, it is available via `apt install upx-ucl` on Debian/Ubuntu systems.

---

## Dynamic Analysis — Running the Binary Locally

Before digging into static analysis, it is always worth simply running the program:

```bash
$ ./hiddencipher
Here your encrypted flag:
235a201d70201548251358110c552f135409
```

The program reads `flag.txt`, encrypts its contents, and prints the result as a hex string. This tells us everything we need — we now have:

|Item|Value|
|---|---|
|**Plaintext** (known)|`picoCTF{fake_flag}`|
|**Ciphertext** (observed)|`235a201d70201548251358110c552f135409`|
|**Cipher** (hinted)|XOR|

This sets up a textbook **Known Plaintext Attack (KPA)**.

---

## The Cryptographic Vulnerability — XOR Known Plaintext Attack

### How XOR Encryption Works

XOR encryption applies the bitwise XOR operation between each byte of the plaintext and a repeating key:

```
ciphertext[i] = plaintext[i] XOR key[i % key_length]
```

### The Core Property That Breaks It

XOR is self-inverse. That means:

```
plaintext XOR key = ciphertext
ciphertext XOR plaintext = key       ← this is the attack
```

If we know both the plaintext and its corresponding ciphertext, we can recover the key directly — **no brute force required**.

---

## Extracting the Key

```python
# Known plaintext (from the local flag.txt)
plaintext  = b"picoCTF{fake_flag}"

# Observed ciphertext (from running the binary locally)
ciphertext = bytes.fromhex("235a201d70201548251358110c552f135409")

# XOR them together to recover the key stream
key_stream = bytes([p ^ c for p, c in zip(plaintext, ciphertext)])
print(key_stream)
# b'S3Cr3tS3Cr3tS3Cr3t'
```

The key stream immediately shows a repeating pattern. Checking for the shortest repeating unit:

```python
for keylen in range(1, len(key_stream) + 1):
    k = key_stream[:keylen]
    if all(key_stream[i] == k[i % keylen] for i in range(len(key_stream))):
        print(f"Key (length {keylen}): {k.decode()}")
        break

# Key (length 6): S3Cr3t
```

**XOR key: `S3Cr3t`**

---

## Verification

Before connecting to the live server, we verify our key is correct by re-encrypting the fake flag and checking it matches the observed output:

```python
key       = b"S3Cr3t"
plaintext = b"picoCTF{fake_flag}"

encrypted = bytes([p ^ key[i % len(key)] for i, p in enumerate(plaintext)])
print(encrypted.hex())
# 235a201d70201548251358110c552f135409  ✓ exact match
```

---

## Getting the Real Flag

### Connect to the Server

```bash
$ nc candy-mountain.picoctf.net 62632
Here your encrypted flag:
<hex_string_from_server>
```

### Decrypt with the Recovered Key

```python
key        = b"S3Cr3t"
server_hex = "<paste hex output from server here>"

ciphertext = bytes.fromhex(server_hex)
flag       = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])

print(flag.decode())
# picoCTF{<real_flag>}
```

---

## Full Exploit Script

```python
#!/usr/bin/env python3
"""
PicoCTF - Hidden Cipher 1
XOR Known Plaintext Attack
Key: S3Cr3t
"""

def xor_decrypt(ciphertext_hex: str, key: bytes) -> str:
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext  = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])
    return plaintext.decode()

if __name__ == "__main__":
    KEY        = b"S3Cr3t"
    server_hex = input("Paste server hex output: ").strip()
    print(f"\nFLAG: {xor_decrypt(server_hex, KEY)}")
```

---

## Key Concepts & Takeaways

### 1. UPX Packing

UPX is a common executable packer used to reduce binary size. It is trivially reversible with `upx -d`, and the presence of the `UPX!` magic bytes in a binary's strings output is an immediate tell. In CTF contexts, a packed binary that cannot be easily analyzed statically is almost always UPX.

### 2. XOR Cipher Weaknesses

XOR encryption is extremely weak when:

- The same key is reused across multiple messages (as here)
- Any portion of the plaintext is known to the attacker

In this challenge, the program **ships its own known plaintext** (`flag.txt` with `picoCTF{fake_flag}`) alongside the binary — a catastrophic design flaw that hands the attacker the key directly.

### 3. Known Plaintext Attack (KPA)

A KPA is one of the most fundamental attacks in classical cryptography. Given `P XOR K = C`, knowledge of any two values immediately yields the third. Strong modern ciphers (AES, ChaCha20) are designed to be secure even under KPA conditions. Simple XOR with a short repeating key is not.

### 4. The "XOR Twice" Hint

Hint 3 — _"What happens when you XOR something twice with the same key?"_ — is pointing at the self-inverse property:

```
(P XOR K) XOR K = P
```

This means decryption and encryption are the **same operation** in XOR. The same script that encrypts also decrypts.

---

## Tools Used

|Tool|Purpose|
|---|---|
|`file`|Identify binary type and packing|
|`strings`|Confirm UPX signature|
|`upx -d`|Unpack the binary|
|Python 3|Key extraction and decryption|
|`netcat`|Connect to remote challenge server|

---

## Summary

```
hiddencipher (UPX packed ELF)
        │
        ▼
  upx -d → unpacked ELF
        │
        ▼
  run locally → ciphertext hex of fake_flag
        │
        ▼
  known_plaintext XOR ciphertext → key = "S3Cr3t"
        │
        ▼
  nc server → real ciphertext hex
        │
        ▼
  ciphertext XOR key → picoCTF{real_flag}
```

The challenge is a clean introduction to XOR cryptanalysis and the concept of known plaintext attacks, wrapped in a UPX unpacking prerequisite. Once the binary is unpacked and the local execution behavior is observed, the attack path is direct and requires no brute force.

---

_Writeup by: GRAVLOCH_ 
_Platform: PicoCTF_ _Date: March 2026_