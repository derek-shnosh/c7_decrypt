# Cisco Type 7 Decrypter

This Python script decrypts Cisco “type 7” passwords. It can:

1. **Parse a file** (with the allowed extensions: `.txt`, `.log`, or `.cisco`) for lines like:
   ```
   username <USERNAME> privilege 15 password 7 <ENCRYPTED>
   ```
2. **Parse a directory** of files (with optional recursion) for the same lines.  
3. **Decrypt a single** raw “type 7” encrypted string.

It uses the “decimal offset + 53-byte key” scheme found in some Cisco devices, rather than the more commonly documented 22-byte key or short array. The first two decimal digits of the encrypted string represent the XOR offset in `[0..15]`.

## Requirements

- Python 3.x

## Usage

```
usage: cisco_type7_decrypt.py [-h] [-s] [-r DEPTH] [-m] target

Decrypt Cisco Type 7 lines in files/directories, or a single string.

positional arguments:
  target                File or directory path (if not using -s), or a raw
                        type-7 string (if -s is set).

optional arguments:
  -h, --help            show this help message and exit
  -s, --string          Interpret the `target` argument as a raw type-7
                        encrypted string.
  -r DEPTH, --depth DEPTH
                        Recursively parse directories up to this depth
                        (default=0 = non-recursive).
  -m, --mask            Mask the decrypted passwords (display <MASKED> 
                        instead of the real plaintext).
```

### Examples

1. **Decrypt a single Type 7 string**:
   ```bash
   ./cisco_type7_decrypt.py -s 15060E1F103A2A373B243A3017
   ```
   If valid, you’ll see output like:
   ```
   Decrypted password: testpassword
   ```

2. **Parse a single file**:
   ```bash
   ./cisco_type7_decrypt.py config.txt
   ```
   - Must have an allowed extension (`.txt`, `.log`, `.cisco`).
   - Any lines matching `username ... privilege 15 password 7 <ENC>` are decrypted.

3. **Parse a directory (non-recursive)**:
   ```bash
   ./cisco_type7_decrypt.py /path/to/configs
   ```
   - Only `.txt`, `.log`, `.cisco` files are scanned.
   - Prints decrypted lines if found.

4. **Parse a directory (recursive)**:
   ```bash
   ./cisco_type7_decrypt.py -r 2 /path/to/configs
   ```
   - Processes `.txt`, `.log`, `.cisco` files down to 2 subdirectory levels.
   - If a directory is empty or no lines are found at any level, it prints an appropriate message.

5. **Mask the decrypted passwords** (e.g., for security audits):
   ```bash
   ./cisco_type7_decrypt.py --mask /path/to/configs
   ```
   - Instead of printing the real plaintext, it displays `<MASKED>` for each found password. 
   - Useful in scenarios where you want to confirm the existence of Type 7 passwords **without** exposing them.

### Behavior

- If you run the script **without** `-s` and provide a **non-existent** path, it prints:
  ```
  Error: file or directory does not exist: /bad/path
  ```
- If you run the script **with** `-s`, it always interprets your argument as a raw Cisco Type 7 encrypted string, **never** checking the filesystem.
- Only **files** ending in `.txt`, `.log`, or `.cisco` are parsed to avoid false positives from other file types.
- After scanning a directory, if no Type 7 passwords are found, a message prints:
  ```
  No Type 7 passwords found in any file in path: /path/to/dir
  ```

### Implementation Details

1. **Decimal Offset**  
   The first two characters of an encrypted string are interpreted as **decimal** (0..15). This is a different approach from the “classic” Type 7, which often uses them as hex. Some Cisco devices (certain ASA versions) store the offset that way.

2. **53-Byte Key**  
   The script uses a longer XOR key than the 22-byte string you may find in older references. This key is:
   ```
   0x64,0x73,0x66,0x64,0x3B,0x6B,0x66,0x6F,0x41,0x2C,
   0x2E,0x69,0x79,0x65,0x77,0x72,0x6B,0x6C,0x64,0x4A,
   0x4B,0x44,0x48,0x53,0x55,0x42,0x73,0x67,0x76,0x63,
   0x61,0x36,0x39,0x38,0x33,0x34,0x6E,0x63,0x78,0x76,
   0x39,0x38,0x37,0x33,0x32,0x35,0x34,0x6B,0x3B,0x66,
   0x67,0x38,0x37
   ```

3. **Allowed Extensions**  
   - `.txt`, `.log`, `.cisco`  
   If you wish to parse other file types, just update the `ALLOWED_EXTENSIONS` set.

4. **Masking for Security Audits**  
   - The `--mask` option is especially useful during internal or external **security assessments**.  
   - It allows you to verify where Type 7 passwords exist in your configs, **without** revealing the actual plaintext.  

5. **Parsing**  
   - We look for lines that start with `username `, then split by whitespace **or** match them with a regex pattern.  
   - If `len(parts) >= 7` and the pattern is `username <USER> privilege 15 password 7 <ENC>`, we attempt to decrypt `<ENC>`.

---

## License

<details>
<summary>This project is licensed under the terms of the MIT License. Expand for the full license text.</summary>

MIT License

Copyright (c) 2025 Derek Smiley

Permission is hereby granted, free of charge, to any person obtaining a copy  
of this software and associated documentation files (the "Software"), to deal  
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN  
THE SOFTWARE.
</details>
