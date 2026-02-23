import argparse
import sys
import os
from pathlib import Path
from typing import Optional, List
from micropki.ca import RootCA, CAError
from micropki.logger import setup_logger, redact_passphrase
from micropki import __version__
import logging

logger = logging.getLogger(__name__)


def validate_key_args(args: argparse.Namespace) -> None:
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise argparse.ArgumentError(
            None,
            f"RSA key size must be 4096 bits, got {args.key_size}"
        )
    elif args.key_type == 'ecc' and args.key_size != 384:
        raise argparse.ArgumentError(
            None,
            f"ECC key size must be 384 bits (P-384), got {args.key_size}"
        )


def validate_passphrase_file(passphrase_file: str) -> None:
    path = Path(passphrase_file)
    if not path.exists():
        raise argparse.ArgumentError(None, f"Passphrase file not found: {passphrase_file}")
    if not os.access(path, os.R_OK):
        raise argparse.ArgumentError(None, f"Passphrase file not readable: {passphrase_file}")


def validate_out_dir(out_dir: str) -> None:
    path = Path(out_dir)
    if path.exists():
        if not os.access(path, os.W_OK):
            raise argparse.ArgumentError(None, f"Output directory not writable: {out_dir}")
    else:
        parent = path.parent
        if not os.access(parent, os.W_OK):
            raise argparse.ArgumentError(None, f"Cannot create directory in: {parent}")


def validate_subject(subject: str) -> None:
    if not subject or not subject.strip():
        raise argparse.ArgumentError(None, "Subject cannot be empty")


def validate_positive_int(value: str) -> int:
    try:
        ivalue = int(value)
        if ivalue <= 0:
            raise argparse.ArgumentError(None, f"Value must be positive: {value}")
        return ivalue
    except ValueError:
        raise argparse.ArgumentError(None, f"Invalid integer: {value}")


def setup_ca_init_parser(subparsers) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        'init',
        help='Initialize a self-signed Root CA',
        description='Create a new self-signed Root Certificate Authority'
    )

    parser.add_argument(
        '--subject',
        required=True,
        help='Distinguished Name (e.g., "/CN=My Root CA" or "CN=My Root CA,O=Demo")'
    )

    parser.add_argument(
        '--key-type',
        choices=['rsa', 'ecc'],
        default='rsa',
        help='Key type (default: rsa)'
    )

    parser.add_argument(
        '--key-size',
        type=int,
        default=4096,
        help='Key size in bits (RSA: 4096, ECC: 384) (default: 4096)'
    )

    parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing the passphrase for private key encryption'
    )

    parser.add_argument(
        '--out-dir',
        default='./pki',
        help='Output directory (default: ./pki)'
    )

    parser.add_argument(
        '--validity-days',
        type=validate_positive_int,
        default=3650,
        help='Validity period in days (default: 3650 ≈ 10 years)'
    )

    parser.add_argument(
        '--log-file',
        help='Optional path to log file (default: stderr)'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force overwrite of existing files'
    )

    return parser


def cmd_ca_init(args: argparse.Namespace) -> int:
    try:
        validate_subject(args.subject)
        validate_key_args(args)
        validate_passphrase_file(args.passphrase_file)
        validate_out_dir(args.out_dir)

        if not args.force:
            private_key_path = Path(args.out_dir) / 'private' / 'ca.key.pem'
            cert_path = Path(args.out_dir) / 'certs' / 'ca.cert.pem'

            if private_key_path.exists() or cert_path.exists():
                response = input(
                    "Output files already exist. Overwrite? [y/N] "
                ).strip().lower()
                if response != 'y' and response != 'yes':
                    print("Operation cancelled.", file=sys.stderr)
                    return 1
        ca = RootCA(out_dir=args.out_dir, log_file=args.log_file)

        if args.log_file:
            for handler in ca.logger.handlers:
                if isinstance(handler, logging.StreamHandler):
                    ca.logger.removeHandler(handler)

        result = ca.init_root_ca(
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase_file=args.passphrase_file,
            validity_days=args.validity_days
        )

        print("\nRoot CA initialized successfully!")
        print(f"Output directory: {result['out_dir']}")
        print(f"Private key: {result['private_key']}")
        print(f"Certificate: {result['certificate']}")
        print(f"Policy document: {result['policy']}")
        print("\nRemember to keep your passphrase secure!")

        return 0

    except (argparse.ArgumentError, CAError) as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nOperation interrupted by user", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:

    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - A minimal Public Key Infrastructure',
        epilog='For more information, see https://github.com/micropki/micropki'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'MicroPKI v{__version__}'
    )

    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        required=True,
        help='Available commands'
    )

    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(
        dest='ca_command',
        required=True,
        help='CA subcommands'
    )

    setup_ca_init_parser(ca_subparsers)

    args = parser.parse_args(argv)

    if args.command == 'ca':
        if args.ca_command == 'init':
            return cmd_ca_init(args)
        else:
            print(f"Unknown CA command: {args.ca_command}", file=sys.stderr)
            return 1
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())