
**Author:** Philip Thayer

**Category:** Reverse Engineering / Pwn

**Difficulty:** Easy–Medium

**Tags:** #picoCTF #reverse-engineering #binary-analysis #djb2 #xor-obfuscation #memory-leak

## Challenge Description

The challenge presents a password authentication system that claims to securely store passwords and verify users through a hash comparison.

Players interact with the program remotely. After setting a password and specifying its length, the program asks the user to provide a hash in order to authenticate.

**Example interaction:**


```plaintext
$ nc candy-mountain.picoctf.net 62979
Please set a password for your account:
123456

How many bytes in length is your password?
6

You entered: 6

Your successfully stored password:
49 50 51 52 53 54 10

Enter your hash to access your account!
```

The goal is to determine how the program generates its hash and submit the correct value to retrieve the flag. This can be achieved through two distinct methods: **Static Analysis** (Reverse Engineering) or **Dynamic Exploitation** (Memory Leak).

---

## Method 1: Static Analysis (Reverse Engineering)

## Initial Reconnaissance

To begin analysis, we inspect the binary using common reverse engineering tools.

**Useful commands:**

```bash
file system.out
strings system.out
objdump -d system.out
```

The binary is an `ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped`. Because it is not stripped, function names remain visible, revealing several interesting symbols:

- `make_secret`
    
- `hash`
    
- `flag.txt`
    
- `strcpy`
    

## Analyzing Secret Generation

Disassembling the `make_secret` function reveals a key instruction:


```codesnippet
xor $0xaa,%eax
```

This indicates the program performs XOR decoding on stored bytes: `secret_byte = obfuscated_byte ^ 0xAA`.

Applying XOR `0xAA` to the obfuscated bytes stored in the binary produces the decoded secret string:

`iUbh81!j*hn!`

## Identifying the Hash Algorithm

The `hash()` function contains a distinctive pattern:


```c
hash = (hash << 5) + hash + c
```

This corresponds to the well-known **DJB2 hashing algorithm**, originally created by Daniel J. Bernstein.

Python implementation to reproduce the hash:


```python
def djb2(s):
    h = 5381
    for c in s:
        h = ((h << 5) + h) + ord(c)
    return h & 0xffffffffffffffff

secret = "iUbh81!j*hn!"
print(djb2(secret))
# Output: 15237662580160011234
```

---

## Method 2: The "Heartbleed-Style" Memory Leak

Alternatively, we can bypass the static analysis of the XOR obfuscation entirely by exploiting a vulnerability in how the program handles user input. The prompt explicitly asks: _"How many bytes in length is your password?"_

If we lie to the program and provide a length larger than our actual password, the program fails to validate our input and simply reads that many bytes from memory. This results in a **Buffer Over-read**, highly reminiscent of the infamous Heartbleed bug.

**Triggering the Leak:**


```plaintext
Please set a password for your account:
123456
How many bytes in length is your password?
72
You entered: 72
Your successfully stored password:
49 50 51 52 53 54 10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 105 85 98 104 56 49 33 106 42 104 110 33 -86
```

The program prints our 7-byte password (`123456\n`), followed by padding zeros, and then dumps the decoded secret straight from adjacent memory!

Converting the leaked decimal bytes (`105 85 98 104 56...`) to ASCII yields our secret: `iUbh81!j*hn!`. From here, we simply run those bytes through the DJB2 hash algorithm as discovered above.

---

## Exploiting the Program

Whether the secret was found via Static Analysis or the Memory Leak, the final step is to submit the computed numeric hash. (Submitting the raw ASCII string causes the C function `strtoul` to fail and crash the program).


```plaintext
$ nc candy-mountain.picoctf.net 58253
Please set a password for your account:
AAAA
How many bytes in length is your password?
4
You entered: 4
Your successfully stored password:
65 65 65 65 10
Enter your hash to access your account!
15237662580160011234
```

Because the supplied hash matches the program’s internally generated value, authentication succeeds and the program prints the flag.

## Flag

`picoCTF{d0nt_trust_us3rs}`

---

## Key Concepts & Takeaways

1. **Unvalidated User Input (Buffer Over-read)**
    
    The flag `d0nt_trust_us3rs` perfectly summarizes the core vulnerability. By trusting the user's stated password length, the program leaked sensitive data (the secret) sitting in adjacent memory.
    
2. **Recognizing Known Hash Algorithms**
    
    Certain patterns immediately identify common algorithms. `hash = (hash << 5) + hash + c` is a signature of the DJB2 hash. Recognizing these patterns speeds up reverse engineering dramatically.
    
3. **XOR Obfuscation**
    
    The secret string was hidden using a simple XOR operation (`byte ^ 0xAA`). While trivial to reverse, XOR obfuscation is widely used in CTF challenges, malware, and packed binaries.
    

## Tools Used

|**Tool**|**Purpose**|
|---|---|
|**file**|Identify binary type|
|**strings**|Extract readable data|
|**objdump**|Disassemble the program|
|**Python 3**|Recreate hashing logic & parse memory leaks|
|**nc (netcat)**|Connect to the challenge server|

## Attack Flow Summary

system.out
      │
      ▼
Disassemble binary
      │
      ▼
Analyze make_secret() → XOR decode bytes
      │
      ▼
Recover secret string
      │
      ▼
Identify DJB2 hash algorithm
      │
      ▼
Recompute hash locally
      │
      ▼
Submit hash to remote service
      │
      ▼
Authentication succeeds
      │
      ▼
Flag revealed



**_Writeup by: GRAVLOCH_**

**_Platform: picoCTF_**

**_Category: Reverse Engineering / Pwn_**

**_Date: 2026_**