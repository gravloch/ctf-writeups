
**Category:** Binary Exploitation / Heap  
**Difficulty:** Medium  
**Tags:** #heap #tcache #free-list #glibc #binary-exploitation

---

## Challenge Description

> You've stumbled upon a mysterious cash register that doesn't keep money — it keeps secrets in memory. Traverse the free list and find all the free chunks to get to the flag.

**Files provided:** `heapedit`, `Makefile`, `libc.so.6`, `heapedit.c`  
**Hint:** Read up on GLIBC's tcache.

---

## Reconnaissance

### Binary Properties

```bash
file heapedit
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

readelf -l heapedit | grep -i stack
# GNU_STACK — RW (no execute, stack not executable)
```

Key observations:

- Non-PIE binary — heap addresses are deterministic across runs
- Dynamically linked — uses the provided `libc.so.6`
- Not stripped — symbol names visible in disassembly

---

## Understanding the Binary

### Program Flow

Reconstructed from disassembly and `strings` output:

```
1. Open and read flag.txt into a stack buffer
2. malloc(0x80) × 6  →  chunks[0..5], all zeroed with memset
3. Copy flag into chunks[0] + 8  (skipping first 8 bytes)
4. Free chunks in reverse order: free(5), free(4), ..., free(0)
5. Print tcache head address
6. Loop: ask user for each chunk address in the free list
7. When traversal reaches NULL fd → print the flag
```

### Heap Layout After Allocations

Each `malloc(0x80)` allocates a **0x90-byte** chunk (0x80 user data + 0x10 header). Since allocations happen sequentially with no intervening frees, the chunks are contiguous in memory:

```
chunk[0]  @ base
chunk[1]  @ base + 0x90
chunk[2]  @ base + 0x120
chunk[3]  @ base + 0x1b0
chunk[4]  @ base + 0x240
chunk[5]  @ base + 0x2d0
```

### Tcache Free List After Frees

GLIBC's tcache is a **LIFO singly-linked list**. Freeing in reverse order (5→4→3→2→1→0) means chunk[0] is freed last and becomes the **head**:

```
tcache[0x90]:  head → chunk[0] → chunk[1] → chunk[2] → chunk[3] → chunk[4] → chunk[5] → NULL
```

Each freed chunk stores a **forward pointer (fd)** in its first 8 bytes pointing to the next chunk in the list.

```
chunk[0].fd = &chunk[1]
chunk[1].fd = &chunk[2]
...
chunk[5].fd = NULL   ← end of list
```

### The Flag Location

The flag is copied into `chunk[0] + 8` — right after where the fd pointer lives. The program prints it once traversal reaches `NULL`.

---

## The Challenge Mechanic

The program:

1. Prints the tcache head address (`chunk[0]`)
2. Asks you to input each chunk address one by one
3. After you input a chunk address, it reads that chunk's fd pointer internally and uses it to validate your next input
4. When the internal fd pointer reads as `NULL` → correct traversal → flag printed

**What we need to provide:** The address of every chunk in the free list, in order.

---

## Solution

### Key Insight

Since the binary is **non-PIE**, heap addresses are the same every run. But more importantly — the program **tells us chunk[0]'s address** directly. Because all chunks are contiguous at `0x90` intervals, we can compute every address from the head alone:

```
chunk[n] = head + n × 0x90
```

We just need to walk the list: `head`, `head+0x90`, `head+0x180`, `head+0x210`, `head+0x2a0`, `head+0x330`.

### Local Testing Note

The challenge ships with its own `libc.so.6`. Running locally against a modern GLIBC (≥ 2.32) will fail because newer versions use **safe-linking** — fd pointers are XOR'd with `chunk_addr >> 12` before being stored. The challenge's libc predates this feature, so fd pointers are raw addresses. Always test with the provided libc using `LD_PRELOAD` or `patchelf`.

### Exploit Script

```python
#!/usr/bin/env python3
"""
heapedit — picoCTF
Tcache free list traversal

Usage:
    python3 solve.py <host> <port>
"""

import sys
import socket
import re

CHUNK_SPACING = 0x90   # malloc(0x80) = 0x80 data + 0x10 header
NUM_CHUNKS    = 6

def recvuntil(sock, delimiter):
    data = b""
    while delimiter not in data:
        data += sock.recv(1)
    return data

def solve(host, port):
    print(f"[*] Connecting to {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    s.settimeout(10)

    # Read the tcache head line
    banner = recvuntil(s, b'\n').decode()
    print(f"[*] {banner.strip()}")

    head = int(banner.split('-> ')[1].strip(), 16)
    print(f"[*] tcache head = {hex(head)}")

    # Compute all chunk addresses from the head
    chunks = [head + i * CHUNK_SPACING for i in range(NUM_CHUNKS)]
    print(f"[*] Computed chunk addresses:")
    for i, addr in enumerate(chunks):
        print(f"    chunk[{i}] = {hex(addr)}")

    # Feed addresses through the traversal loop
    for i, addr in enumerate(chunks):
        prompt = recvuntil(s, b': ').decode()
        print(f"[*] {prompt.strip()}")
        payload = hex(addr) + '\n'
        print(f"[>] Sending {payload.strip()}")
        s.send(payload.encode())

    # Collect final output
    import time
    time.sleep(1)
    response = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
    except Exception:
        pass

    output = response.decode(errors='replace')
    print(f"\n[*] Server response:\n{output}")

    flag = re.search(r'picoCTF\{[^}]+\}', output)
    if flag:
        print(f"\n[+] FLAG: {flag.group()}")
    else:
        print("[!] Flag not found — verify chunk spacing and libc version")

    s.close()

if __name__ == '__main__':
    if len(sys.argv) == 3:
        solve(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python3 solve.py <host> <port>")
        sys.exit(1)
```

### Running It

```bash
# Launch the challenge instance on picoCTF, then:
python3 solve.py <host> <port>
```

**Expected output:**

```
[*] Connecting to <host>:<port>
[*] tcache head (start of free list) -> 0x603480
[*] tcache head = 0x603480
[*] Computed chunk addresses:
    chunk[0] = 0x603480
    chunk[1] = 0x603510
    chunk[2] = 0x6035a0
    chunk[3] = 0x603630
    chunk[4] = 0x6036c0
    chunk[5] = 0x603750
[*] Chunk 1 address:
[>] Sending 0x603480
[*] Chunk 2 address:
[>] Sending 0x603510
...
[+] FLAG: picoCTF{...}
```

---

## Concepts Covered

### Tcache (Thread Local Caching)

Introduced in GLIBC 2.26. A per-thread cache of recently freed chunks, organised as a singly-linked list per size class. Up to 7 chunks per bin. Much faster than the main allocator because it skips locking.

### Free List Structure

When a chunk is freed into tcache, the allocator writes the address of the next free chunk into the first 8 bytes of the freed chunk's user data region (the fd pointer). The tcache bin header points to the most recently freed chunk. Traversal: follow fd pointers until NULL.

```
[chunk header: size | prev_size]
[fd pointer → next free chunk ]  ← first 8 bytes of user data
[remaining user data           ]
```

### Safe-Linking (GLIBC ≥ 2.32)

Mitigates tcache poisoning attacks by mangling stored fd pointers:

```c
// Store:  stored_fd = real_next XOR (chunk_addr >> 12)
// Fetch:  real_next = stored_fd XOR (chunk_addr >> 12)
```

This challenge predates safe-linking — fd pointers are raw addresses on the remote server.

---

## Key Takeaways

- **Read the binary, not just the description.** The program's output tells you exactly where the heap is. Work with what you're given.
- **Non-PIE means deterministic addresses.** No ASLR on the heap base when PIE is disabled.
- **Tcache is LIFO.** The last chunk freed becomes the head of the free list. Freeing in reverse order (5→0) puts chunk[0] at the head.
- **Contiguous allocations are predictable.** Same-size mallocs with no intervening frees sit exactly `chunk_size` apart.
- **Always use the provided libc.** Modern system libc will behave differently. `LD_PRELOAD=./libc.so.6 ./heapedit` for accurate local testing.

---

## References

- [GLIBC tcache implementation](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c)
- [Safe-Linking explained — Check Point Research](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/)
- [Heap exploitation — how2heap](https://github.com/shellphish/how2heap)
- [pwn.college — Heap Exploitation module](https://pwn.college/program-security/heap-exploitation/)

---

_— gravloch_