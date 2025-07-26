# pylint: disable=missing-docstring

import os

from c7_decrypt import (
    decrypt_password,
    parse_file,
    process_file,
    process_directory,
)

# Point to the samples directory under tests/
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def test_decrypt_password_known_values():
    samples = {
        "1403171818142B38373F3C2726": "testpassword",
        "00101615104B0A151C36435C0D4B": "testpassword2",
        "044F0E151B2E5F5E0F12000E": "testospfkey",
        "071B245F5A1D1806161118070133": "testtacacskey"
    }
    for encrypted_pw, expected_plaintext in samples.items():
        ok, result = decrypt_password(encrypted_pw)
        assert ok, f"Expected decryption to succeed for {encrypted_pw}"
        assert result == expected_plaintext


def test_parse_valid_file():
    valid_file = os.path.join(SAMPLES_DIR, "valid.txt")
    user_entries, ospf_entries, tacacs_entries = parse_file(valid_file)

    # Two valid user entries
    assert len(user_entries) == 2

    # Build the set of successfully decrypted usernames explicitly
    usernames = set()
    for entry in user_entries:
        username, _, _, success = entry
        if success:
            usernames.add(username)

    assert usernames == {"testadmin", "testadmin2"}

    # One valid OSPF entry
    assert len(ospf_entries) == 1
    intf_name, key_id, decrypted_key, ok = ospf_entries[0]
    assert intf_name == "Vlan800"
    assert key_id == "1"
    assert decrypted_key == "testospfkey"
    assert ok

    # One valid TACACS entry
    assert len(tacacs_entries) == 1
    server_name, server_key, ok = tacacs_entries[0]
    assert server_name == "TACACS_1"
    assert server_key == "testtacacskey"
    assert ok


def test_parse_invalid_file():
    invalid_file = os.path.join(SAMPLES_DIR, "invalid.txt")
    user_entries, ospf_entries, tacacs_entries = parse_file(invalid_file)
    assert not user_entries
    assert not ospf_entries
    assert not tacacs_entries


def test_process_file_outputs(capsys):
    valid_file = os.path.join(SAMPLES_DIR, "valid.txt")

    # Without masking
    assert process_file(valid_file, mask_decrypted=False)
    out = capsys.readouterr().out
    assert "testpassword" in out
    assert "testpassword2" in out
    assert "testospfkey" in out
    assert "testtacacskey" in out

    # With masking
    assert process_file(valid_file, mask_decrypted=True)
    out = capsys.readouterr().out
    assert "<MASKED>" in out
    # Confirm plaintext not shown in masked mode
    assert "testpassword" not in out.splitlines()[1]


def test_process_file_invalid():
    invalid_file = os.path.join(SAMPLES_DIR, "invalid.txt")
    assert not process_file(invalid_file)


# Cannot have an empty folder in Git.
# def test_process_directory_empty(capsys):
#     empty_dir = os.path.join(SAMPLES_DIR, "emptyfolder")
#     result = process_directory(empty_dir, max_depth=0, mask_decrypted=False)
#     out = capsys.readouterr().out
#     assert not result
#     assert "No files found in directory" in out


def test_process_directory_with_only_invalid(capsys):
    bad_dir = os.path.join(SAMPLES_DIR, "folderwithinvalidfiles")
    result = process_directory(bad_dir, max_depth=0, mask_decrypted=False)
    out = capsys.readouterr().out
    assert not result
    # Should be silent (directory not empty but no valid entries)
    assert out == ""


def test_process_directory_valid_non_recursive(capsys):
    good_dir = os.path.join(SAMPLES_DIR, "folderwithvalidfiles")
    result = process_directory(good_dir, max_depth=0, mask_decrypted=False)
    out = capsys.readouterr().out
    assert result
    assert "testpassword" in out
    assert "testospfkey" in out


def test_process_directory_recursive(capsys):
    # Recursively scan the samples directory itself
    result = process_directory(SAMPLES_DIR, max_depth=1, mask_decrypted=False)
    out = capsys.readouterr().out
    assert result
    # Should find credentials in both top-level valid.txt and folderwithvalidfiles/valid.txt
    assert out.count("testpassword") >= 2
