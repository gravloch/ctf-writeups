**Author:**  SkrubLawd

**Category:** Reverse Engineering

**Difficulty:** Easy–Medium

**Tags:** #picoCTF #reverse-engineering #binary-analysis #pwntools #automation #assembly

---

# Challenge Description

The challenge server claims to be extremely good at reverse engineering and challenges the player to prove otherwise.

The server sends **20 compiled binaries**, each encoded as **hexadecimal bytes**. For every binary:

- Extract the **secret number**
    
- Send it back to the server
    
- Do this **within 1 second**
    

If all responses are correct, the server reveals the flag.

Example prompt from the server:

```
Welcome! I think I'm pretty good at reverse engineering.
There's NO WAY anyone's better than me.

I have 20 binaries I'm going to send you and you have
1 second EACH to get the secret in each one.
Good luck >:)
```

---

# Provided Challenge Setup

The challenge does not provide downloadable files directly. Instead, binaries are streamed dynamically over a network connection.

To interact with the challenge we connect using:

```bash
nc mysterious-sea.picoctf.net 59692
```

Each binary arrives encoded as **hexadecimal bytes**.

---

# Initial Reconnaissance

## Step 1 — Understanding the Binary Structure

To understand the challenge, the first step is to inspect one of the provided binaries.

If we reconstruct the binary locally, the typical workflow would look like this:

### Reconstruct the Binary

```bash
echo <hex_binary> | xxd -r -p > binary
chmod +x binary
```

Check file type:

```bash
file binary
```

Expected output:

```
ELF 64-bit LSB executable
```

---

## Step 2 — Static Analysis

Next, we disassemble the binary using:

```bash
objdump -d binary
```

or analyze it with tools such as:

- Ghidra
    
- GDB
    

During analysis we observe a repeating structure in the assembly.

Example snippet:

```
c7 45 fc 67 ae e5 48
```

This instruction translates to:

```
mov DWORD PTR [rbp-0x4], 0x48e5ae67
```

This tells us that the program stores a **hardcoded secret value** in memory.

---

# Reverse Engineering the Logic

After reconstructing the program flow, we can approximate the source code.

```c
#include <stdio.h>

int main() {

    unsigned int secret = CONSTANT;
    unsigned int input;

    printf("What's the secret?\n");

    scanf("%u", &input);

    if (input == secret) {
        puts("Correct!");
    } else {
        puts("Nice try :(");
    }

}
```

The binary simply compares the user input with a **constant value embedded in the executable**.

Because the binary uses:

```
scanf("%u")
```

the secret must be supplied in **unsigned decimal format**.

---

# The Key Observation

All 20 binaries are compiled using the **same template**.

Only one thing changes:

```
mov DWORD PTR [rbp-0x4], SECRET
```

This instruction always begins with the same **opcode sequence**:

```
c7 45 fc
```

The **next 4 bytes** represent the secret value in **little-endian format**.

Example:

```
c7 45 fc 67 ae e5 48
```

Which becomes:

```
secret = 0x48e5ae67
```

Converted to decimal:

```
1223011943
```

Because this pattern is constant across all binaries, we can **automate the extraction**.

---

# The Exploitation — Automated Binary Parsing

Instead of manually reversing 20 binaries, we build a Python script to:

1. Receive the hex binary
    
2. Convert it into raw bytes
    
3. Search for the opcode pattern
    
4. Extract the secret
    
5. Send the result back instantly
    

---

## Automation Script (`Decryptor4.py`)

Using the exploitation framework:

pwntools

```python
from pwn import *

r = remote("mysterious-sea.picoctf.net",59692)

print(r.recvline())

while True:

    line = r.recvline().decode()

    if "Here's the next binary in bytes:" in line:

        hexdata = r.recvline().strip().decode()

        binary = bytes.fromhex(hexdata)

        idx = binary.find(b"\xc7\x45\xfc")

        secret = int.from_bytes(binary[idx+3:idx+7], "little")

        print(secret)

        r.sendline(str(secret))

    else:
        print(line)
```

---

# Script Execution

Running the script automatically solves all 20 binaries.

Example output:

```
447066649
Correct!

4061322641
Correct!

802915873
Correct!

...

2513524594
Correct!

Woah, how'd you do that??

Here's your flag:
picoCTF{4u7o_r3v_g0_brrr_78c345aa}
```

The `EOFError` occurs because the server closes the connection after sending the flag, which is expected behavior.

---

# Getting the Flag

After solving all binaries successfully, the server reveals the flag.

**Flag:**

```
picoCTF{4u7o_r3v_g0_brrr_78c345aa}
```

---

# Key Concepts & Takeaways

### 1. Pattern-Based Reverse Engineering

When binaries are compiled from identical templates, assembly patterns remain constant. Identifying these patterns allows rapid extraction of secrets.

---

### 2. Automation in CTF Challenges

Manual reverse engineering would take **10–30 seconds per binary**.

Automation reduces solving time to **milliseconds**, making it possible to beat strict time limits.

---

### 3. Little-Endian Encoding

The secret value is stored as a 4-byte immediate constant in **little-endian order**, meaning the byte sequence must be reversed when interpreting the integer.

---

### 4. Binary Opcode Recognition

Recognizing compiler-generated instructions such as:

```
mov DWORD PTR [rbp-0x4], IMM32
```

is a powerful reverse engineering technique.

---

# Tools Used

|Tool|Purpose|
|---|---|
|**netcat**|Connect to the remote challenge server|
|**pwntools**|Automate interaction and binary parsing|
|**objdump**|Disassemble ELF binaries|
|**Ghidra**|Static binary analysis|
|**Python 3**|Extract and convert the secret values|

---

# Summary

```
Remote Server
      │
      ▼
Receive Hex-Encoded Binary
      │
      ▼
Convert Hex → Raw Bytes
      │
      ▼
Search Opcode Pattern (c7 45 fc)
      │
      ▼
Extract Immediate Value
      │
      ▼
Convert Little Endian → Decimal
      │
      ▼
Send Answer Automatically
      │
      ▼
Solve 20 Binaries
      │
      ▼
Receive Flag
```

---

**Writeup by:** GRAVLOCH

**Platform:** PicoCTF

**Date:** March 2026



