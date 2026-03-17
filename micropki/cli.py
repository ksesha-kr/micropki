import argparse
import sys
import os
from pathlib import Path
from typing import Optional, List
from micropki.ca import RootCA, CAError
from micropki.chain import verify_chain, get_chain_info
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


def setup_ca_init_parser(subparsers):
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


def setup_ca_issue_intermediate_parser(subparsers):
    parser = subparsers.add_parser(
        'issue-intermediate',
        help='Issue an Intermediate CA signed by the Root CA',
        description='Create a new Intermediate CA certificate signed by the Root CA'
    )

    parser.add_argument('--root-cert', required=True, help='Path to Root CA certificate (PEM)')
    parser.add_argument('--root-key', required=True, help='Path to Root CA encrypted private key (PEM)')
    parser.add_argument('--root-pass-file', required=True, help='File containing passphrase for Root CA key')
    parser.add_argument('--subject', required=True, help='Distinguished Name for the Intermediate CA')
    parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type (default: rsa)')
    parser.add_argument('--key-size', type=int, default=4096, help='Key size in bits (RSA: 4096, ECC: 384)')
    parser.add_argument('--passphrase-file', required=True, help='Passphrase for Intermediate CA private key')
    parser.add_argument('--out-dir', default='./pki', help='Output directory (default: ./pki)')
    parser.add_argument('--validity-days', type=int, default=1825,
                        help='Validity period in days (default: 1825 ≈ 5 years)')
    parser.add_argument('--pathlen', type=int, default=0, help='Path length constraint (default: 0)')
    parser.add_argument('--log-file', help='Optional path to log file')

    return parser


def setup_ca_issue_cert_parser(subparsers):
    parser = subparsers.add_parser(
        'issue-cert',
        help='Issue an end-entity certificate',
        description='Issue a server, client, or code signing certificate signed by an Intermediate CA'
    )

    parser.add_argument('--ca-cert', required=True, help='Intermediate CA certificate (PEM)')
    parser.add_argument('--ca-key', required=True, help='Intermediate CA encrypted private key (PEM)')
    parser.add_argument('--ca-pass-file', required=True, help='Passphrase for Intermediate CA key')
    parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'],
                        help='Certificate template')
    parser.add_argument('--subject', required=True, help='Distinguished Name for the certificate')
    parser.add_argument('--san', action='append', help='Subject Alternative Name (e.g., dns:example.com)')
    parser.add_argument('--out-dir', default='./pki/certs', help='Output directory (default: ./pki/certs)')
    parser.add_argument('--validity-days', type=int, default=365, help='Validity period in days (default: 365)')
    parser.add_argument('--csr', help='Optional CSR file to sign instead of generating new key')
    parser.add_argument('--log-file', help='Optional path to log file')

    return parser


def setup_chain_verify_parser(subparsers):
    parser = subparsers.add_parser(
        'verify',
        help='Verify certificate chain',
        description='Verify the full certificate chain: leaf → intermediate → root'
    )

    parser.add_argument('--leaf', required=True, help='Leaf certificate path')
    parser.add_argument('--intermediate', required=True, help='Intermediate certificate path')
    parser.add_argument('--root', required=True, help='Root certificate path')

    return parser


def cmd_ca_init(args):
    try:
        validate_subject(args.subject)
        validate_key_args(args)
        validate_passphrase_file(args.passphrase_file)

        from micropki.ca import RootCA
        ca = RootCA(out_dir=args.out_dir, log_file=args.log_file)

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

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_issue_intermediate(args):
    try:
        validate_key_args(args)
        validate_passphrase_file(args.root_pass_file)
        validate_passphrase_file(args.passphrase_file)

        from micropki.ca import RootCA
        ca = RootCA(out_dir=args.out_dir, log_file=args.log_file)

        result = ca.issue_intermediate(
            root_cert_path=args.root_cert,
            root_key_path=args.root_key,
            root_passphrase_file=args.root_pass_file,
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase_file=args.passphrase_file,
            validity_days=args.validity_days,
            pathlen=args.pathlen
        )

        print("\nIntermediate CA issued successfully!")
        print(f"Output directory: {args.out_dir}")
        print(f"Private key: {result['private_key']}")
        print(f"Certificate: {result['certificate']}")
        print(f"CSR: {result['csr']}")

        return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_issue_cert(args):
    try:
        validate_subject(args.subject)

        if not os.path.exists(args.out_dir):
            os.makedirs(args.out_dir, mode=0o755)

        from micropki.ca import RootCA
        ca = RootCA(out_dir=str(Path(args.out_dir).parent), log_file=args.log_file)

        result = ca.issue_certificate(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase_file=args.ca_pass_file,
            template=args.template,
            subject=args.subject,
            san_entries=args.san,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            csr_path=args.csr
        )

        print(f"\n{args.template.capitalize()} certificate issued successfully!")
        print(f"Certificate: {result['certificate']}")
        if 'private_key' in result:
            print(f"Private key: {result['private_key']}")
            print("\nWARNING: Private key is stored unencrypted!")

        return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_chain_verify(args):
    try:
        if verify_chain(args.leaf, args.intermediate, args.root):
            info = get_chain_info(args.leaf, args.intermediate, args.root)
            print("\nChain validation successful!")
            print("\nChain Information:")
            print(f"  Root: {info['root']['subject']}")
            print(f"  Intermediate: {info['intermediate']['subject']}")
            print(f"  Leaf: {info['leaf']['subject']}")
            return 0
        else:
            print("\nChain validation failed!", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - A minimal Public Key Infrastructure',
        epilog='For more information, see https://github.com/ksesha-kr/micropki'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='MicroPKI v0.2.0'
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
    setup_ca_issue_intermediate_parser(ca_subparsers)
    setup_ca_issue_cert_parser(ca_subparsers)

    chain_parser = subparsers.add_parser('chain', help='Chain validation operations')
    chain_subparsers = chain_parser.add_subparsers(
        dest='chain_command',
        required=True,
        help='Chain subcommands'
    )
    setup_chain_verify_parser(chain_subparsers)

    args = parser.parse_args(argv)

    if args.command == 'ca':
        if args.ca_command == 'init':
            return cmd_ca_init(args)
        elif args.ca_command == 'issue-intermediate':
            return cmd_ca_issue_intermediate(args)
        elif args.ca_command == 'issue-cert':
            return cmd_ca_issue_cert(args)
        else:
            print(f"Unknown CA command: {args.ca_command}", file=sys.stderr)
            return 1
    elif args.command == 'chain':
        if args.chain_command == 'verify':
            return cmd_chain_verify(args)
        else:
            print(f"Unknown chain command: {args.chain_command}", file=sys.stderr)
            return 1
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
