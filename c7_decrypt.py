#!/usr/bin/env python3

"""
Decrypt Cisco type 7 password(s) from file(s) or a string.
"""

import os
import platform
import re
import argparse

# Windows platform check
IS_WINDOWS = platform.system() == "Windows"

# Extended XOR key (53 bytes) for decimal-offset Type 7
KEY_HEX = (
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C,
    0x2E, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6B, 0x6C, 0x64, 0x4A,
    0x4B, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63,
    0x61, 0x36, 0x39, 0x38, 0x33, 0x34, 0x6E, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B, 0x3B, 0x66,
    0x67, 0x38, 0x37
)

# Files must end with one of these extensions to be parsed
ALLOWED_EXTENSIONS = {'.txt', '.log', '.cisco'}

# Capture two groups: <USER> and <ENCRYPTED_PASSWORD>
USERPASS_PATTERN = re.compile(
    r'^username\s+(\S+)\s+privilege\s+15\s+password\s+7\s+(\S+)',
    re.MULTILINE
)

# Text formatting variables.
BOLD = "" if IS_WINDOWS else "\033[1m"
RESET = "" if IS_WINDOWS else "\033[0m"


def decrypt_password(encrypted: str):
    """
    Thanks for help here, ChatGPT! :D

    Decrypt a string as a Cisco Type 7 password using decimal offset [0..15]
    plus the 53-byte key KEY_HEX.
    Returns True/False (as decryption_ok), result:
      - decryption_ok = True => result is the decrypted plaintext
      - decryption_ok = False => result is an error message
    """
    if len(encrypted) < 4 or len(encrypted) > 52 or (len(encrypted) % 2) != 0:
        return (False, "Error! Bad password length.")

    try:
        offset = int(encrypted[:2])  # decimal parse (e.g. '15' => offset=15)
        if not 0 <= offset <= 15:
            return (False, "Error! Bad key offset.")

        hex_payload = encrypted[2:]
        plaintext = []
        for i in range(0, len(hex_payload), 2):
            enc_val = int(hex_payload[i : i + 2], 16)
            key_val = KEY_HEX[((i // 2) + offset) % len(KEY_HEX)]
            dec_val = enc_val ^ key_val
            plaintext.append(chr(dec_val))
        return (True, "".join(plaintext))

    except ValueError:
        return (False, "Error! Invalid encryption data.")


def parse_file(filepath: str):
    """
    Reads the entire file into memory and uses a multiline regex to find:
      username <USER> privilege 15 password 7 <ENCRYPTED>
    Returns a list of (username, decrypted_pw, decryption_ok) tuples.
    """
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            file_contents = f.read()  # Read entire file as one string

        # Find all matches at once
        matches = USERPASS_PATTERN.findall(file_contents)
        # matches is now a list of tuples [(<USER>, <ENC>), (<USER>, <ENC>), ...]

        for user, encrypted_pw in matches:
            decryption_ok, decrypted_pw = decrypt_password(encrypted_pw)
            results.append((user, decrypted_pw, decryption_ok))

    except (IOError, OSError) as e:
        print(f"Error reading file '{filepath}': {e}")

    return results


def process_file(filepath: str, mask=False) -> bool:
    """
    Parses a single file for type 7 lines.
    Prints them. Returns True if any found, else False.
    """
    results = parse_file(filepath)
    if not results:
        return False

    print(f"File: {BOLD}{os.path.abspath(filepath)}{RESET}")
    for user, decrypted_pw, decryption_ok in results:
        if decryption_ok:
            if mask:
                print(f"  Username: {user}, Decrypted Password: <MASKED>")
            else:
                print(f"  Username: {user}, Decrypted Password: {decrypted_pw}")
        else:
            print(f"  Username: {user}, ERROR: {decrypted_pw}")
    return True


def process_directory(dirpath: str, max_depth: int, current_depth: int = 0, mask=False) -> bool:
    """
    Recursively processes `dirpath` up to `max_depth` levels deep.
    - If directory is empty and current_depth=0 => prints "No files found..."
    - Only parse ALLOWED_EXTENSIONS
    - Returns True if any Type 7 lines found, else False
    """
    entries = list(os.scandir(dirpath))
    if not entries and current_depth == 0:
        print(f"No files found in directory: {os.path.abspath(dirpath)}")
        return False

    found_any = False
    for entry in entries:
        if entry.is_file():
            _, file_extension = os.path.splitext(entry.name)
            if file_extension.lower() in ALLOWED_EXTENSIONS:
                found_in_file = process_file(entry.path, mask=mask)
                if found_in_file:
                    found_any = True
        elif entry.is_dir():
            if current_depth < max_depth:
                sub_found = process_directory(entry.path, max_depth, current_depth + 1, mask=mask)
                if sub_found:
                    found_any = True
    return found_any


def main():
    """
    Main script logic.
    """
    parser = argparse.ArgumentParser(
        description="Decrypt Cisco Type 7 lines in files/directories, or a single string."
    )
    parser.add_argument(
        "target",
        help="File or directory path (if not using -s), or a raw type-7 string (if -s is set).",
    )
    parser.add_argument(
        "-s",
        "--string",
        action="store_true",
        help="Interpret the `target` argument as a raw type-7 encrypted string.",
    )
    parser.add_argument(
        "-r",
        "--depth",
        type=int,
        default=0,
        help="Recursively parse directories up to this depth (default=0 = non-recursive).",
    )
    parser.add_argument(
        "-m",
        "--mask",
        action="store_true",
        default=False,
        help="Mask the decrypted passwords (show <MASKED> instead)."
    )
    args = parser.parse_args()

    # If -s is given => treat the argument as a raw type 7 string
    if args.string:
        decryption_ok, result = decrypt_password(args.target)
        if decryption_ok:
            if args.mask:
                print(f"Decrypted password: {BOLD}<MASKED>{RESET}")
            else:
                print(f"Decrypted password: {BOLD}{result}{RESET}")
        else:
            print(f"Could not decrypt '{args.target}': {result}")
        return

    # Otherwise, treat `target` as a path
    path = args.target
    if not os.path.exists(path):
        print(f"Error: file or directory does not exist: {path}")
        return

    if os.path.isdir(path):
        found = process_directory(path, args.depth, mask=args.mask)
        if not found:
            # If not empty, print the final message
            entries = list(os.scandir(path))
            if entries:  # not empty
                print(
                    f"No Type 7 passwords found in any file in path: {os.path.abspath(path)}"
                )
    elif os.path.isfile(path):
        # Check file extension
        _, file_extension = os.path.splitext(path)
        if file_extension.lower() in ALLOWED_EXTENSIONS:
            found_in_file = process_file(path, mask=args.mask)
            if not found_in_file:
                print(f"No Type 7 passwords found in file: {os.path.abspath(path)}")
        else:
            print(f"File extension not allowed for: {os.path.abspath(path)}")
    else:
        # path is something unusual (pipe/symlink?), or not recognized
        print(f"Error: path is neither a regular file nor a directory: {path}")


if __name__ == "__main__":
    main()
