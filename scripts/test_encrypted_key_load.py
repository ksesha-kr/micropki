import argparse
import sys
from pathlib import Path
from micropki.crypto_utils import load_encrypted_private_key, read_passphrase_from_file


def test_encrypted_key_load(key_path: str, passphrase_file: str):
    try:
        passphrase = read_passphrase_from_file(passphrase_file)

        private_key = load_encrypted_private_key(key_path, passphrase)

        print(f"Successfully loaded encrypted private key from {key_path}")
        print(f"   Key type: {type(private_key).__name__}")
        return True

    except Exception as e:
        print(f"Failed to load encrypted key: {str(e)}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test loading encrypted private key")
    parser.add_argument("--key", required=True, help="Path to encrypted private key file")
    parser.add_argument("--passphrase-file", required=True, help="Path to passphrase file")

    args = parser.parse_args()

    success = test_encrypted_key_load(args.key, args.passphrase_file)
    sys.exit(0 if success else 1)