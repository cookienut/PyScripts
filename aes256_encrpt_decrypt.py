"""
A bunch of utility methods for encryption/decryption and a simple
CLI invokable main method for encrypting/decrypting data from
files using AES-256 ciphering technique and a secret password.

Encrypts text from ``plaintext.txt`` and writes to ``encrypted.txt``.
Decrypts encrypted data from ``encrypted.txt``.

For installation use: ``pip install click pbkdf2 pyaes``
For how to run,  use: ``python aes256_encrpt_decrypt.py --help``

Author: dev.sagarbhat@gmail.com (Sagar Bhat)
Github: @cookienut

Inspired by Svetlin Nakov's blog on Symmetric Key Ciphers:
https://cryptobook.nakov.com/symmetric-key-ciphers
"""

# pylint: disable = invalid-name, no-value-for-parameter, redefined-outer-name

import os
import sys

import binascii
import getpass
import secrets

from pathlib import Path

import click
import pbkdf2
import pyaes


def read_password(prompt=None):
    """
    Accept password as user input and return the same.
    """
    prompt_text = prompt or "Please enter pass phrase (hidden): "
    return getpass.getpass(prompt=prompt_text)

def generate_key(password, password_salt):
    """
    Derive a 256-bit AES encryption key from the password and password salt.
    """
    key = pbkdf2.PBKDF2(password, password_salt).read(32)
    return key

def hexlify(text_string):
    """
    Return decoded hexadecimal representation of binary data.
    """
    return binascii.hexlify(text_string).decode("utf8")

def unhexlify(text_string):
    """
    Return binary data represented by the decoded hexadecimal string.
    """
    return binascii.unhexlify(text_string.encode("utf8"))

def encrypt(iv, key, plaintext):
    """
    Encrypt the plaintext with the given key:
    ciphertext = AES-256-CTR-Encrypt(plaintext, key, iv)
    """
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    return ciphertext

def decrypt(iv, key, ciphertext):
    """
    Decrypt the ciphertext with the given key:
    plaintext = AES-256-CTR-Decrypt(ciphertext, key, iv)
    """
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    return decrypted

def read_from_file(file_name):
    """
    Read text from the given file.
    """
    # Make sure filename only contains name of file
    file_name = os.path.split(file_name)[-1]
    # Find absolute path of file
    _base_path = Path(__file__).resolve().parent
    _file_path = Path.joinpath(_base_path, file_name)
    try:
        with open(_file_path, "r") as fh:
            return fh.readlines()
    except FileNotFoundError:
        print(f"\nError: File '{file_name}' not found...")
        sys.exit(1)

def write_to_file(file_name, lines):
    """
    Write provided text lines to the given file.
    """
    # Make sure filename only contains name of file
    file_name = os.path.split(file_name)[-1]
    # Find absolute path of file
    _base_path = Path(__file__).resolve().parent
    _file_path = Path.joinpath(_base_path, file_name)
    try:
        with open(_file_path, "w") as fh:
            for each_line in lines:
                fh.write(each_line)
    except FileNotFoundError:
        print(f"\nError: File '{file_name}' not found...")
        sys.exit(1)

def encrypt_file(read_from, write_to, post_encryption_erase=False):
    """
    Encrypt data from a text file with plain text and write the AES-256
    encrypted data to another file. Returns None.
    """
    # Accept password
    password = read_password()
    # Generate Initialization Vector, Password Salt and Cipher Key
    iv = secrets.randbits(256)
    ps = os.urandom(16)
    key = generate_key(password, ps)

    # Add iv and password salt as initial values in cipher text
    ciphertext = list(map(lambda val: f"{str(val)}\n", [iv, hexlify(ps)]))

    # Read plain text lines (text to encrypt)
    plain_text_lines = read_from_file(read_from)
    # Encrypt each line into a cipher
    for each_line in plain_text_lines:
        __encrypted = encrypt(iv, key, each_line)
        # Convert bytes to string
        ciphertext.append(f"{hexlify(__encrypted)}\n")

    # Write encrypted text to the specified file
    write_to_file(file_name=write_to, lines=ciphertext)

    # Erase data from original source file after successful encrypting
    if post_encryption_erase:
        write_to_file(file_name=read_from, lines=[""])


def decrypt_file(file_name):
    """
    Decrypt data from an AES-256 encrypted text file and returns the
    decrypted text as a string.
    """
    # Accept password
    password = read_password()
    # Read encrypted file
    file_content = read_from_file(file_name)

    # Retrieve iv, password salt and encrypted data
    iv = int(file_content[0].rstrip("\n"))
    ps = unhexlify(file_content[1].rstrip("\n"))
    encrypted_data = file_content[2::]

    # Generate cipher key
    key = generate_key(password, ps)
    # Parse ciphers (convert to bytes)
    ciphers = [unhexlify(line.rstrip("\n")) for line in encrypted_data]

    # Decrypt each cipher and print decrpted value on terminal or cmd
    try:
        plaintext = []
        for each_cipher in ciphers:
            __decrypted = decrypt(iv, key, each_cipher).decode("utf8")
            plaintext.append(__decrypted)
        return "".join(plaintext)

    except UnicodeDecodeError:
        print("Error decoding text, possibly wrong passphrase.")
        sys.exit(1)


# Provide CLI options for encryption and decryption
@click.command("main", short_help="Encrypt or Decrypt data using AES-256")
@click.option("--decrypt", "-d", is_flag=True, help="Flag to decrypt")
@click.option("--encrypt", "-e", is_flag=True, help="Flag to encrypt")
def main(encrypt, decrypt):
    """
    Encrypt or Decrypt data using AES-256 ciphering technique.

    To encrypt use:
        python aes256_encrpt_decrypt.py -e

    To decrypt use:
        python aes256_encrpt_decrypt.py -d
    """

    if encrypt:
        # Encrypt data and keep source file contents after encryption
        # To erase file contents: set `post_encryption_erase` to `True`
        encrypt_file(
            read_from="plaintext.txt",
            write_to="encrypted.txt",
            post_encryption_erase=False
        )
        print("Encryption complete.")

    if decrypt:
        plaintext = decrypt_file(file_name="encrypted.txt")
        print("Decryption complete. Plain text:")
        print(plaintext)

    # Exit message
    print("\nThank you. [ Developed by Sagar Bhat (@cookienut) ]")


if __name__ == "__main__":
    main()
