
**Category:** Reverse Engineering / Cryptography

**Author:** Yahaya Meddy

**Tags:** #picoCTF, #reverse-engineering, #cryptography, #python, #math-cipher

## 📝 Challenge Description

> "The flag is right in front of you... kind of. You just need to solve a basic math problem to see it. But to get the real flag, you’ll have to understand how that math answer is used."
> 
> **Hints:**
> 
> 1. Focus on what the program does with your correct answer. Is it reused later?
>     
> 2. Disassembling or decompiling tools (Ghidra, IDA) can help reveal the exact transformation on the flag.
>     

---

## 🔍 Initial Reconnaissance

Connecting to the provided netcat instance prompts us with a simple math question. Answering it correctly yields a large array of numbers.

```python
#!/usr/bin/env python3

def decode_flag():
    # The output array from the server
    encoded_values = [
        3920, 3675, 3465, 3885, 2345, 2940, 2450, 4305, 3815, 1820, 4060, 3640, 
        3325, 3430, 1785, 3640, 1715, 3850, 3500, 3325, 3465, 1715, 3920, 3640, 
        1785, 3990, 3325, 3535, 1925, 1715, 1820, 1995, 1785, 1715, 1960, 4375
    ]
    
    # The answer to 7 * 5 used as the multiplier key
    key = 35
    
    # Divide each value by the key and convert back to an ASCII character
    flag = "".join(chr(val // key) for val in encoded_values)
    
    return flag

if __name__ == "__main__":
    print(f"[*] Decoded Flag: {decode_flag()}")

```

Output:

```plaintext
$ python3 decryptor.py
[*] Decoded Flag: picoCTF{m4th_b3h1nd_c1ph3r_e7149318}

```
## 🏁 Final Flag

`picoCTF{m4th_b3h1nd_c1ph3r_e7149318}`
