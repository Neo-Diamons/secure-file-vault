#!/usr/bin/python3

import argparse
import getpass
import os
import sys

from cryptography.fernet import InvalidToken

from tui.core import Tui
from utils.encryption import Encryption


def get_parser():
    parser = argparse.ArgumentParser(
        description="Secure File Vault (Encryption & Decryption Tool)"
    )
    subparsers = parser.add_subparsers(title="commands", dest="command")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument(
        "filepath",
        help="Path to the input file to encrypt",
    )
    encrypt_parser.add_argument(
        "-p",
        "--password",
        help="Password to use for encryption (if omitted, will prompt)",
    )

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument(
        "filepath",
        help="Path to the encrypted input file to decrypt",
    )
    decrypt_parser.add_argument(
        "-p",
        "--password",
        help="Password to use for decryption (if omitted, will prompt)",
    )

    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()

    if args.command == "encrypt":
        if not os.path.exists(args.filepath):
            print("Error: File does not exist.", file=sys.stderr)
            return
        encryption = Encryption()
        if encryption.is_encrypted(args.filepath):
            print("Error: File is already encrypted.", file=sys.stderr)
            return
        if not args.password:
            args.password = getpass.getpass("Enter encryption password: ")
        try:
            encryption.encrypt_file(
                input_filename=args.filepath,
                output_filename=args.filepath + ".encrypted",
                password=args.password,
            )
        except Exception:
            print("Error: Encryption failed.", file=sys.stderr)
            return
        os.remove(args.filepath)
    elif args.command == "decrypt":
        if not os.path.exists(args.filepath):
            print("Error: File does not exist.", file=sys.stderr)
            return
        encryption = Encryption()
        if not encryption.is_encrypted(args.filepath):
            print("Error: File is not encrypted.", file=sys.stderr)
            return
        if not args.password:
            args.password = getpass.getpass("Enter decryption password: ")
        try:
            encryption.decrypt_file(
                input_filename=args.filepath,
                output_filename=args.filepath.removesuffix(".encrypted"),
                password=args.password,
            )
        except InvalidToken:
            print("Error: Decryption failed. Invalid password.", file=sys.stderr)
            return
        except Exception:
            print("Error: Decryption failed.", file=sys.stderr)
            return
        os.remove(args.filepath)
    else:
        app = Tui()
        app.run()


if __name__ == "__main__":
    main()
