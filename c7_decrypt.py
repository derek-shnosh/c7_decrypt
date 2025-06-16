#!/usr/bin/env python3

"""
Decrypt Cisco type 7 password(s) from file(s) or a string.
"""

import os
import platform
import re
import argparse
import sys
import csv

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
    r"^username (\S+) privilege 15 password 7 (\S+)",
    re.MULTILINE
)

# Capture one group: <INTF_NAME>
INTFCONFIG_PATTERN = re.compile(
    r"^interface (\S+)(.*?)(?=^\s*interface\s|\Z)",
    re.MULTILINE | re.DOTALL
)

# Capture one group: <OSPF_KEY>
OSPFKEY_PATTERN = re.compile(
    r"^\s+ip ospf message-digest-key (\d+) md5 7 (\S+)",
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
    - username ... password 7 <encrypted_pw>
    - ip ospf message-digest-key <keyid> md5 7 <encrypted_pw>

    Returns two lists:
      user_results = [(username, decrypted_or_error, decryption_ok), ...]
      ospf_results = [(intf_name, key_id, decrypted_or_error, decryption_ok), ...]
    """

    # Store contents of file
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            file_contents = file.read()
    except (IOError, OSError) as e:
        print(f"Error reading file '{filepath}': {e}")
        return [], []

    # Find all type 7 user passwords
    user_results = []
    for user, encrypted_pw in USERPASS_PATTERN.findall(file_contents):
        decryption_ok, decrypted_pw = decrypt_password(encrypted_pw)
        user_results.append((user, decrypted_pw, decryption_ok))

    # Find all type 7 OSPF keys
    ospf_results = []
    for intf_match in INTFCONFIG_PATTERN.finditer(file_contents):
        intf_name = intf_match.group(1)
        intf_config = intf_match.group(2)
        for key_id, encrypted_pw in OSPFKEY_PATTERN.findall(intf_config):
            decryption_ok, decrypted_pw = decrypt_password(encrypted_pw)
            ospf_results.append((intf_name, key_id, decrypted_pw, decryption_ok))

    return user_results, ospf_results


def process_file(filepath: str, mask_decrypted: bool = False) -> bool:
    """
    Parses a single file for user passwords and OSPF keys (of type 7) and prints
    them.

    Returns True if any found, else False.
    """
    user_pws, ospf_keys = parse_file(filepath)
    if not user_pws and not ospf_keys:
        return False

    # Print file name in bold
    print(f"File: {BOLD}{os.path.abspath(filepath)}{RESET}")

    # Print decrypted user passwords
    for user, decrypted_pw, decryption_ok in user_pws:
        if decryption_ok:
            output = "<MASKED>" if mask_decrypted else decrypted_pw
            print(f"  Username: {user}, Decrypted Password: {output}")
        else:
            print(f"  Username: {user}, ERROR: {decrypted_pw}")

    # Print decrypted OSPF keys
    for intf_name, key_id, decrypted_pw, decryption_ok in ospf_keys:
        if decryption_ok:
            output = "<MASKED>" if mask_decrypted else decrypted_pw
            print(f"  Interface {intf_name}, OSPF key {key_id}: {output}")
        else:
            print(f"  Interface {intf_name}, OSPF Key {key_id}, ERROR: {decrypted_pw}")

    return True


def process_directory(
    dirpath: str,
    max_depth: int,
    current_depth: int = 0,
    mask_decrypted: bool = False
) -> bool:
    """
    Recursively processes `dirpath` up to `max_depth` levels deep.
    - If directory is completely empty (only at top level), print "No files
     found..." and return False.
    - Otherwise scan for ALLOWED_FILES (and recurse), and return True if any
     were processed.
    """
    # Get list of files in specified path
    try:
        entries = list(os.scandir(dirpath))
    except (IOError, OSError) as e:
        print(f"Error opening directory '{dirpath}': {e}")
        return False

    # If no files or subdirectories
    if not entries and current_depth == 0:
        print(f"No files found in directory: {os.path.abspath(dirpath)}")
        return False

    # Look for files with allowed file extensions, parse them for type 7s
    found_any = False
    for entry in entries:
        if entry.is_file():
            _, file_extension = os.path.splitext(entry.name)
            if file_extension.lower() in ALLOWED_EXTENSIONS:
                if process_file(entry.path, mask_decrypted):
                    found_any = True
        elif entry.is_dir() and current_depth < max_depth:
            if process_directory(
                entry.path,
                max_depth,
                current_depth + 1,
                mask_decrypted
            ):
                found_any = True
    return found_any


def output_csv(target_path: str, max_depth: int, mask_decrypted: bool):
    """
    Output all decrypted user passwords and OSPF keys in CSV format.

    CSV Columns:
      file, username, decrypted_password, ospf_interface, ospf_key_id, ospf_key

    Recursively scans directories up to `max_depth`. Outputs to stdout.
    """
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "file",
        "username",
        "decrypted_password",
        "ospf_interface",
        "ospf_key_id",
        "ospf_key",
    ])

    to_scan = []
    if os.path.isfile(target_path):
        to_scan.append(target_path)
    else:
        base_depth = target_path.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(target_path):
            if (root.count(os.sep) - base_depth) >= max_depth:
                dirs.clear()
            for name in files:
                if os.path.splitext(name)[1].lower() in ALLOWED_EXTENSIONS:
                    to_scan.append(os.path.join(root, name))

    for filepath in to_scan:
        abs_path = os.path.abspath(filepath)
        users, ospfs = parse_file(filepath)
        for user, pw, ok in users:
            if ok:
                pw_out = "<MASKED>" if mask_decrypted else pw
                writer.writerow([abs_path, user, pw_out, "", "", ""])
        for intf, keyid, pw, ok in ospfs:
            if ok:
                pw_out = "<MASKED>" if mask_decrypted else pw
                writer.writerow([abs_path, "", "", intf, keyid, pw_out])


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
        "-m",
        "--mask",
        action="store_true",
        default=False,
        help="Mask the decrypted passwords (show <MASKED> instead)."
    )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=0,
        help="Recursively parse directories up to this depth (default=0 = non-recursive).",
    )
    parser.add_argument(
        "-c",
        "--csv",
        action="store_true",
        default=False,
        help="Output results in CSV format."
    )
    args = parser.parse_args()

    # Warn if CSV is requested in string mode
    if args.string and args.csv:
        print(
            "Warning: CSV output is ignored when using -s/--string mode",
            file=sys.stderr
        )
        # clear the flag so it won't be used:
        args.csv = False

    # CSV output? (only when not in string mode)
    if args.csv:
        output_csv(args.target, args.depth, args.mask)
        return

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
        found = process_directory(path, args.depth, mask_decrypted=args.mask)
        if not found:
            # If not empty, print the final message
            entries = list(os.scandir(path))
            if entries:  # not empty
                print(
                    f"No Type 7s found in any file in path: {os.path.abspath(path)}"
                )
    elif os.path.isfile(path):
        # Check file extension
        _, file_extension = os.path.splitext(path)
        if file_extension.lower() in ALLOWED_EXTENSIONS:
            found_in_file = process_file(path, mask_decrypted=args.mask)
            if not found_in_file:
                print(f"No Type 7 passwords found in file: {os.path.abspath(path)}")
        else:
            print(f"File extension not allowed for: {os.path.abspath(path)}")
    else:
        # path is something unusual (pipe/symlink?), or not recognized
        print(f"Error: path is neither a regular file nor a directory: {path}")


if __name__ == "__main__":
    main()
