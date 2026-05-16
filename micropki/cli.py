import argparse
import sys
import os
from pathlib import Path
from typing import Optional, List
from micropki.ca import RootCA, CAError
from micropki.chain import verify_chain, get_chain_info
from micropki.config import MicroPKIConfig, ConfigError
import logging
from datetime import datetime

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


def setup_db_init_parser(subparsers):
    parser = subparsers.add_parser(
        'init',
        help='Initialize certificate database',
        description='Create SQLite database schema for certificate storage'
    )

    parser.add_argument(
        '--db-path',
        default='./pki/micropki.db',
        help='Path to SQLite database (default: ./pki/micropki.db)'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Recreate database if it exists'
    )

    return parser


def setup_ca_list_certs_parser(subparsers):
    parser = subparsers.add_parser(
        'list-certs',
        help='List issued certificates',
        description='Display all certificates from the database'
    )

    parser.add_argument(
        '--status',
        choices=['valid', 'revoked', 'expired'],
        help='Filter by certificate status'
    )

    parser.add_argument(
        '--format',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )

    parser.add_argument(
        '--db-path',
        default='./pki/micropki.db',
        help='Path to SQLite database (default: ./pki/micropki.db)'
    )

    return parser


def setup_ca_show_cert_parser(subparsers):
    parser = subparsers.add_parser(
        'show-cert',
        help='Show certificate by serial number',
        description='Retrieve and display a certificate from the database'
    )

    parser.add_argument(
        'serial',
        help='Certificate serial number in hexadecimal format'
    )

    parser.add_argument(
        '--format',
        choices=['pem', 'text'],
        default='pem',
        help='Output format (default: pem)'
    )

    parser.add_argument(
        '--db-path',
        default='./pki/micropki.db',
        help='Path to SQLite database (default: ./pki/micropki.db)'
    )

    return parser


def setup_repo_serve_parser(subparsers):
    parser = subparsers.add_parser('serve', help='Start repository HTTP server')

    parser.add_argument('--host', default='127.0.0.1', help='Bind address')
    parser.add_argument('--port', type=int, default=8080, help='TCP port')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')
    parser.add_argument('--cert-dir', default='./pki/certs', help='Certificate directory')
    parser.add_argument('--log-file', help='Log file path')

    parser.add_argument('--enable-ocsp', action='store_true', help='Enable OCSP endpoint')
    parser.add_argument('--ocsp-responder-cert', help='OCSP signing certificate')
    parser.add_argument('--ocsp-responder-key', help='OCSP private key')
    parser.add_argument('--ocsp-ca-cert', help='Issuer CA certificate for OCSP')
    parser.add_argument('--ocsp-cache-ttl', type=int, default=60, help='OCSP cache TTL in seconds')

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


def cmd_db_init(args):
    try:
        from micropki.database import CertificateDatabase

        db_path = Path(args.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        if args.force and db_path.exists():
            db_path.unlink()
            print(f"Removed existing database: {db_path}")

        db = CertificateDatabase(str(db_path))
        db.init_schema()
        db.close()

        print(f"Database initialized successfully at {db_path}")
        return 0

    except Exception as e:
        print(f"Error initializing database: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_list_certs(args):
    try:
        from micropki.database import CertificateDatabase
        import json
        import csv
        import sys

        db = CertificateDatabase(args.db_path)
        certificates = db.list_certificates(status=args.status)
        db.close()

        if args.format == 'json':
            output = []
            for cert in certificates:
                output.append({
                    'serial': cert['serial_hex'],
                    'subject': cert['subject'],
                    'issuer': cert['issuer'],
                    'not_before': cert['not_before'],
                    'not_after': cert['not_after'],
                    'status': cert['status']
                })
            print(json.dumps(output, indent=2))

        elif args.format == 'csv':
            writer = csv.writer(sys.stdout)
            writer.writerow(['Serial', 'Subject', 'Issuer', 'Not Before', 'Not After', 'Status'])
            for cert in certificates:
                writer.writerow([
                    cert['serial_hex'],
                    cert['subject'],
                    cert['issuer'],
                    cert['not_before'],
                    cert['not_after'],
                    cert['status']
                ])

        else:
            print(f"{'Serial':<20} {'Subject':<40} {'Status':<10}")
            print("-" * 70)
            for cert in certificates:
                subject = cert['subject'][:40]
                print(f"{cert['serial_hex']:<20} {subject:<40} {cert['status']:<10}")
            print(f"\nTotal: {len(certificates)} certificates")

        return 0

    except Exception as e:
        print(f"Error listing certificates: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_show_cert(args):
    try:
        from micropki.database import CertificateDatabase
        from micropki.serial import validate_serial_hex
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        if not validate_serial_hex(args.serial):
            print("Invalid serial number format. Must be hexadecimal.", file=sys.stderr)
            return 1

        db = CertificateDatabase(args.db_path)
        cert_record = db.get_certificate_by_serial(args.serial)
        db.close()

        if not cert_record:
            print(f"Certificate with serial {args.serial} not found", file=sys.stderr)
            return 1

        if args.format == 'text':
            cert = x509.load_pem_x509_certificate(
                cert_record['cert_pem'].encode(),
                default_backend()
            )
            print(f"Certificate:")
            print(f"  Serial: {cert_record['serial_hex']}")
            print(f"  Subject: {cert_record['subject']}")
            print(f"  Issuer: {cert_record['issuer']}")
            print(f"  Valid From: {cert_record['not_before']}")
            print(f"  Valid To: {cert_record['not_after']}")
            print(f"  Status: {cert_record['status']}")
        else:
            print(cert_record['cert_pem'])

        return 0

    except Exception as e:
        print(f"Error showing certificate: {str(e)}", file=sys.stderr)
        return 1


def cmd_repo_serve(args):
    try:
        from micropki.repository import RepositoryServer
        from micropki.logger import setup_logger

        if args.log_file:
            setup_logger("micropki.repo", args.log_file)

        if args.enable_ocsp:
            if not all([args.ocsp_responder_cert, args.ocsp_responder_key, args.ocsp_ca_cert]):
                print("Error: --enable-ocsp requires --ocsp-responder-cert, --ocsp-responder-key, and --ocsp-ca-cert",
                      file=sys.stderr)
                return 1

        server = RepositoryServer(
            db_path=args.db_path,
            cert_dir=args.cert_dir,
            host=args.host,
            port=args.port,
            enable_ocsp=args.enable_ocsp,
            ocsp_responder_cert=args.ocsp_responder_cert,
            ocsp_responder_key=args.ocsp_responder_key,
            ocsp_ca_cert=args.ocsp_ca_cert,
            ocsp_cache_ttl=args.ocsp_cache_ttl
        )

        print(f"Starting repository server on {args.host}:{args.port}")
        if args.enable_ocsp:
            print(f"OCSP endpoint available at http://{args.host}:{args.port}/ocsp")
        print("Press Ctrl+C to stop")

        server.start()

        return 0

    except KeyboardInterrupt:
        print("\nServer stopped")
        return 0
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

def setup_ca_revoke_parser(subparsers):
    parser = subparsers.add_parser(
        'revoke',
        help='Revoke a certificate',
        description='Revoke an issued certificate by serial number'
    )

    parser.add_argument('serial', help='Certificate serial number in hexadecimal format')
    parser.add_argument('--reason', default='unspecified',
                        choices=['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                                 'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL',
                                 'privilegeWithdrawn', 'aACompromise'],
                        help='Revocation reason (default: unspecified)')
    parser.add_argument('--force', action='store_true', help='Skip confirmation prompt')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Path to SQLite database')

    return parser


def setup_ca_gen_crl_parser(subparsers):
    parser = subparsers.add_parser(
        'gen-crl',
        help='Generate Certificate Revocation List',
        description='Generate CRL for specified CA'
    )

    parser.add_argument('--ca', required=True, choices=['root', 'intermediate'],
                        help='CA type to generate CRL for')
    parser.add_argument('--ca-cert', help='Path to CA certificate (auto-detected if not specified)')
    parser.add_argument('--ca-key', help='Path to CA private key (auto-detected if not specified)')
    parser.add_argument('--ca-pass-file', help='Path to passphrase file for CA key')
    parser.add_argument('--next-update', type=int, default=7, help='Days until next CRL update (default: 7)')
    parser.add_argument('--out-file', help='Output file path (default: auto-generated)')
    parser.add_argument('--out-dir', default='./pki', help='Output directory (default: ./pki)')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Path to SQLite database')
    parser.add_argument('--log-file', help='Optional path to log file')

    return parser


def setup_ca_check_revoked_parser(subparsers):
    parser = subparsers.add_parser(
        'check-revoked',
        help='Check if a certificate is revoked',
        description='Check revocation status by serial number'
    )

    parser.add_argument('serial', help='Certificate serial number in hexadecimal format')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Path to SQLite database')

    return parser


def cmd_ca_revoke(args):
    try:
        from micropki.ca import RootCA
        from micropki.serial import validate_serial_hex

        if not validate_serial_hex(args.serial):
            print("Invalid serial number format. Must be hexadecimal.", file=sys.stderr)
            return 1

        ca = RootCA(out_dir='.', log_file=None)
        result = ca.revoke_certificate(
            serial_hex=args.serial,
            reason=args.reason,
            db_path=args.db_path,
            force=args.force
        )

        if result['status'] == 'already_revoked':
            print(f"Certificate {args.serial} is already revoked")
            return 0
        elif result['status'] == 'cancelled':
            print("Revocation cancelled")
            return 0
        elif result['status'] == 'revoked':
            print(f"Certificate {args.serial} revoked successfully")
            print(f"   Reason: {args.reason}")
            return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_gen_crl(args):
    try:
        from micropki.ca import RootCA
        from pathlib import Path

        out_dir = Path(args.out_dir)

        if args.ca == 'root':
            ca_cert = args.ca_cert or str(out_dir / 'certs' / 'ca.cert.pem')
            ca_key = args.ca_key or str(out_dir / 'private' / 'ca.key.pem')
            ca_pass = args.ca_pass_file or str(out_dir.parent / 'secrets' / 'root.pass')
        else:
            ca_cert = args.ca_cert or str(out_dir / 'certs' / 'intermediate.cert.pem')
            ca_key = args.ca_key or str(out_dir / 'private' / 'intermediate.key.pem')
            ca_pass = args.ca_pass_file or str(out_dir.parent / 'secrets' / 'intermediate.pass')

        ca = RootCA(out_dir=str(out_dir), log_file=args.log_file)
        result = ca.generate_crl(
            ca_type=args.ca,
            ca_cert_path=ca_cert,
            ca_key_path=ca_key,
            ca_passphrase_file=ca_pass,
            db_path=args.db_path,
            out_dir=args.out_dir,
            next_update_days=args.next_update,
            out_file=args.out_file
        )

        print(f"\nCRL generated successfully!")
        print(f"File: {result['crl_path']}")
        print(f"CRL Number: {result['crl_number']}")
        print(f"Revoked certificates: {result['revoked_count']}")
        print(f"Next update: {result['next_update_days']} days")

        return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_ca_check_revoked(args):
    try:
        from micropki.ca import RootCA
        from micropki.serial import validate_serial_hex

        if not validate_serial_hex(args.serial):
            print("Invalid serial number format. Must be hexadecimal.", file=sys.stderr)
            return 1

        ca = RootCA(out_dir='.', log_file=None)
        result = ca.check_revoked(args.serial, args.db_path)

        if not result['exists']:
            print(f"Certificate with serial {args.serial} not found", file=sys.stderr)
            return 1

        if result['revoked']:
            print(f"Certificate {args.serial} is REVOKED")
            if result.get('revocation_reason'):
                print(f"   Reason: {result['revocation_reason']}")
            if result.get('revocation_date'):
                print(f"   Date: {result['revocation_date']}")
            return 0
        else:
            print(f"Certificate {args.serial} is VALID")
            return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def setup_ca_issue_ocsp_cert_parser(subparsers):
    parser = subparsers.add_parser(
        'issue-ocsp-cert',
        help='Issue OCSP responder certificate',
        description='Issue a special-purpose OCSP signing certificate'
    )

    parser.add_argument('--ca-cert', required=True, help='CA certificate path')
    parser.add_argument('--ca-key', required=True, help='CA private key path')
    parser.add_argument('--ca-pass-file', required=True, help='CA passphrase file')
    parser.add_argument('--subject', required=True, help='Subject DN')
    parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type')
    parser.add_argument('--key-size', type=int, default=2048, help='Key size (RSA: 2048+, ECC: 256)')
    parser.add_argument('--san', action='append', help='Subject Alternative Name')
    parser.add_argument('--out-dir', default='./pki/certs', help='Output directory')
    parser.add_argument('--validity-days', type=int, default=365, help='Validity days')
    parser.add_argument('--db-path', help='Database path for auto-storage')
    parser.add_argument('--log-file', help='Log file path')

    return parser


def setup_ocsp_serve_parser(subparsers):
    parser = subparsers.add_parser(
        'serve',
        help='Start OCSP responder',
        description='Start OCSP responder server'
    )

    parser.add_argument('--host', default='127.0.0.1', help='Bind address')
    parser.add_argument('--port', type=int, default=8081, help='TCP port')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')
    parser.add_argument('--responder-cert', required=True, help='OCSP signing certificate')
    parser.add_argument('--responder-key', required=True, help='OCSP private key')
    parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate')
    parser.add_argument('--cache-ttl', type=int, default=60, help='Cache TTL in seconds')
    parser.add_argument('--log-file', help='Log file path')

    return parser


def cmd_ca_issue_ocsp_cert(args):
    try:
        from micropki.ca import RootCA

        ca = RootCA(out_dir='.', log_file=args.log_file)
        result = ca.issue_ocsp_certificate(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            ca_passphrase_file=args.ca_pass_file,
            subject=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            out_dir=args.out_dir,
            validity_days=args.validity_days,
            san_entries=args.san,
            db_path=args.db_path
        )

        print(f"\nOCSP responder certificate issued successfully!")
        print(f"Certificate: {result['certificate']}")
        print(f"Private key: {result['private_key']}")
        print("\nWARNING: Private key is stored unencrypted!")

        return 0

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def setup_client_gen_csr_parser(subparsers):
    parser = subparsers.add_parser('gen-csr', help='Generate private key and CSR')
    parser.add_argument('--subject', required=True, help='Distinguished Name')
    parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa', help='Key type')
    parser.add_argument('--key-size', type=int, default=2048, help='Key size (RSA: 2048/4096, ECC: 256/384)')
    parser.add_argument('--san', action='append', help='Subject Alternative Name')
    parser.add_argument('--out-key', default='./key.pem', help='Output private key file')
    parser.add_argument('--out-csr', default='./request.csr.pem', help='Output CSR file')
    return parser


def setup_client_request_cert_parser(subparsers):
    parser = subparsers.add_parser('request-cert', help='Submit CSR and get certificate')
    parser.add_argument('--csr', required=True, help='CSR file path')
    parser.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'],
                        help='Certificate template')
    parser.add_argument('--ca-url', required=True, help='Repository base URL')
    parser.add_argument('--out-cert', default='./cert.pem', help='Output certificate file')
    parser.add_argument('--api-key', help='API key for authentication')
    return parser


def setup_client_validate_parser(subparsers):
    parser = subparsers.add_parser('validate', help='Validate certificate chain')
    parser.add_argument('--cert', required=True, help='Leaf certificate path')
    parser.add_argument('--untrusted', action='append', help='Intermediate certificate path')
    parser.add_argument('--trusted', default='./pki/certs/ca.cert.pem', help='Trusted root certificate')
    parser.add_argument('--crl', help='CRL file or URL')
    parser.add_argument('--ocsp', action='store_true', help='Perform OCSP check')
    parser.add_argument('--validation-time', help='Validation time (ISO 8601)')
    parser.add_argument('--format', choices=['text', 'json'], default='text', help='Output format')
    return parser


def setup_client_check_status_parser(subparsers):
    parser = subparsers.add_parser('check-status', help='Check revocation status')
    parser.add_argument('--cert', required=True, help='Certificate path')
    parser.add_argument('--ca-cert', required=True, help='Issuer CA certificate')
    parser.add_argument('--crl', help='CRL file or URL')
    parser.add_argument('--ocsp-url', help='OCSP responder URL')
    return parser


def cmd_client_gen_csr(args):
    try:
        from micropki.client import PKIClient
        client = PKIClient()
        result = client.generate_csr(
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            san_entries=args.san,
            out_key=args.out_key,
            out_csr=args.out_csr
        )
        print(f"CSR generated successfully!")
        print(f"Private key: {result['key']}")
        print(f"CSR: {result['csr']}")
        print("\nWARNING: Private key is stored unencrypted!")
        return 0
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_client_request_cert(args):
    try:
        from micropki.client import PKIClient
        client = PKIClient()
        result = client.request_certificate(
            csr_path=args.csr,
            template=args.template,
            ca_url=args.ca_url,
            out_cert=args.out_cert,
            api_key=args.api_key
        )
        print(f"Certificate issued successfully!")
        print(f"Certificate: {result['certificate']}")
        return 0
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_client_validate(args):
    try:
        from micropki.validation import PathValidator
        from micropki.revocation_check import RevocationChecker
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import json

        with open(args.cert, 'rb') as f:
            leaf = x509.load_pem_x509_certificate(f.read(), default_backend())

        intermediates = []
        if args.untrusted:
            for path in args.untrusted:
                with open(path, 'rb') as f:
                    intermediates.append(x509.load_pem_x509_certificate(f.read(), default_backend()))

        roots = []
        with open(args.trusted, 'rb') as f:
            roots.append(x509.load_pem_x509_certificate(f.read(), default_backend()))

        validation_time = None
        if args.validation_time:
            validation_time = datetime.fromisoformat(args.validation_time)

        validator = PathValidator(validation_time)
        result = validator.validate_chain(leaf, intermediates, roots, 'server')

        if args.format == 'json':
            print(json.dumps(result.to_dict(), indent=2))
        else:
            if result.passed:
                print("Chain validation PASSED")
            else:
                print("Chain validation FAILED")
            print(f"\nChain: {' → '.join([c.subject.rfc4514_string() for c in result.chain])}")
            for step in result.steps:
                status = "PASSED" if step['passed'] else "FAILED"
                print(f"  {status} [{step['step']}] {step.get('message', '')}")

        return 0 if result.passed else 1
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_client_check_status(args):
    try:
        from micropki.revocation_check import RevocationChecker
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        with open(args.cert, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(args.ca_cert, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        checker = RevocationChecker()
        result = checker.check_status(cert, ca_cert, args.ocsp_url, None, args.crl)

        if result['status'] == 'good':
            print(f"Certificate is GOOD (checked via {result['method']})")
        elif result['status'] == 'revoked':
            print(f"Certificate is REVOKED (checked via {result['method']})")
            if result['reason']:
                print(f"   Reason: {result['reason']}")
            if result['revocation_date']:
                print(f"   Date: {result['revocation_date']}")
        else:
            print(f"Certificate status: UNKNOWN (checked via {result['method']})")

        return 0
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def cmd_ocsp_serve(args):
    try:
        from micropki.ocsp_responder import OCSPResponder
        from micropki.logger import setup_logger

        if args.log_file:
            setup_logger("micropki.ocsp", args.log_file)

        responder = OCSPResponder(
            db_path=args.db_path,
            responder_cert_path=args.responder_cert,
            responder_key_path=args.responder_key,
            ca_cert_path=args.ca_cert,
            host=args.host,
            port=args.port,
            cache_ttl=args.cache_ttl
        )

        print(f"Starting OCSP responder on {args.host}:{args.port}")
        print(f"Database: {args.db_path}")
        print(f"Cache TTL: {args.cache_ttl}s")
        print("Press Ctrl+C to stop")

        responder.start()

        return 0

    except KeyboardInterrupt:
        print("\nOCSP responder stopped")
        return 0
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1


def setup_audit_query_parser(subparsers):
    parser = subparsers.add_parser('query', help='Query audit logs')
    parser.add_argument('--from', dest='from_time', help='Start timestamp (ISO 8601)')
    parser.add_argument('--to', dest='to_time', help='End timestamp (ISO 8601)')
    parser.add_argument('--level', choices=['INFO', 'WARNING', 'ERROR', 'AUDIT'], help='Log level')
    parser.add_argument('--operation', help='Operation type')
    parser.add_argument('--serial', help='Certificate serial')
    parser.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    parser.add_argument('--verify', action='store_true', help='Verify integrity')
    parser.add_argument('--out-dir', default='./pki', help='PKI output directory')
    return parser


def setup_audit_verify_parser(subparsers):
    parser = subparsers.add_parser('verify', help='Verify audit log integrity')
    parser.add_argument('--log-file', help='Path to audit log file')
    parser.add_argument('--chain-file', help='Path to chain file')
    parser.add_argument('--out-dir', default='./pki', help='PKI output directory')
    return parser


def setup_audit_ct_verify_parser(subparsers):
    parser = subparsers.add_parser('ct-verify', help='Verify certificate in CT log')
    parser.add_argument('--serial', required=True, help='Certificate serial number')
    parser.add_argument('--out-dir', default='./pki', help='PKI output directory')
    return parser


def setup_ca_compromise_parser(subparsers):
    parser = subparsers.add_parser('compromise', help='Simulate private key compromise')
    parser.add_argument('--cert', required=True, help='Path to certificate')
    parser.add_argument('--reason', default='keyCompromise', help='Revocation reason')
    parser.add_argument('--force', action='store_true', help='Skip confirmation')
    parser.add_argument('--db-path', default='./pki/micropki.db', help='Database path')
    parser.add_argument('--out-dir', default='./pki', help='PKI output directory')
    return parser


def cmd_audit_query(args):
    from micropki.audit import get_audit_logger
    import json
    import csv
    import sys

    audit = get_audit_logger(args.out_dir)
    results = audit.query(
        from_time=getattr(args, 'from_time', None),
        to_time=args.to_time,
        level=args.level,
        operation=args.operation,
        serial=args.serial
    )

    if args.format == 'json':
        print(json.dumps(results, indent=2))
    elif args.format == 'csv':
        if results:
            writer = csv.DictWriter(sys.stdout, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    else:
        print(f"{'Timestamp':<30} {'Level':<8} {'Operation':<20} {'Status':<10} {'Message'}")
        print("-" * 80)
        for entry in results:
            print(
                f"{entry['timestamp']:<30} {entry['level']:<8} {entry['operation']:<20} {entry['status']:<10} {entry['message'][:50]}")

    if args.verify:
        passed, idx = audit.verify()
        if not passed:
            print(f"\n❌ Integrity check FAILED at entry {idx}", file=sys.stderr)
            return 1
        print("\n✅ Integrity check PASSED")
    return 0


def cmd_audit_verify(args):
    from micropki.audit import get_audit_logger

    audit = get_audit_logger(args.out_dir)
    passed, idx = audit.verify()

    if passed:
        print("✅ Audit log integrity verification PASSED")
        return 0
    else:
        print(f"❌ Audit log integrity verification FAILED at entry {idx}", file=sys.stderr)
        return 1


def cmd_audit_ct_verify(args):
    from micropki.audit import get_audit_logger

    audit = get_audit_logger(args.out_dir)
    if audit.ct_verify(args.serial):
        print(f"✅ Certificate {args.serial} found in CT log")
        return 0
    else:
        print(f"❌ Certificate {args.serial} NOT found in CT log", file=sys.stderr)
        return 1


def cmd_ca_compromise(args):
    from micropki.ca import RootCA

    ca = RootCA(out_dir=args.out_dir)
    result = ca.compromise_certificate(
        cert_path=args.cert,
        reason=args.reason,
        db_path=args.db_path,
        force=args.force
    )

    if result['status'] == 'cancelled':
        print("Operation cancelled")
        return 0
    elif result['status'] == 'compromised':
        print(f"✅ Certificate {result['serial']} marked as compromised and revoked")
        return 0
    else:
        print(f"❌ Operation failed", file=sys.stderr)
        return 1

_config = None

def get_config():
    global _config
    if _config is None:
        _config = MicroPKIConfig()
    return _config

def setup_common_args(parser):
    parser.add_argument('--config', help='Path to configuration file (YAML or JSON)')




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

    parser.add_argument(
        '--config',
        help='Path to configuration file'
    )

    subparsers = parser.add_subparsers(
        title='commands',
        dest='command',
        required=True,
        help='Available commands'
    )

    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command', required=True)
    setup_db_init_parser(db_subparsers)

    repo_parser = subparsers.add_parser('repo', help='Repository operations')
    repo_subparsers = repo_parser.add_subparsers(dest='repo_command', required=True)
    setup_repo_serve_parser(repo_subparsers)

    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(
        dest='ca_command',
        required=True,
        help='CA subcommands'
    )

    setup_ca_init_parser(ca_subparsers)
    setup_ca_issue_intermediate_parser(ca_subparsers)
    setup_ca_issue_cert_parser(ca_subparsers)
    setup_ca_list_certs_parser(ca_subparsers)
    setup_ca_show_cert_parser(ca_subparsers)
    setup_ca_revoke_parser(ca_subparsers)
    setup_ca_gen_crl_parser(ca_subparsers)
    setup_ca_check_revoked_parser(ca_subparsers)
    setup_ca_issue_ocsp_cert_parser(ca_subparsers)

    ocsp_parser = subparsers.add_parser('ocsp', help='OCSP responder operations')
    ocsp_subparsers = ocsp_parser.add_subparsers(dest='ocsp_command', required=True)
    setup_ocsp_serve_parser(ocsp_subparsers)

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
    elif args.command == 'db':
        if args.db_command == 'init':
            return cmd_db_init(args)
    elif args.command == 'repo':
        if args.repo_command == 'serve':
            return cmd_repo_serve(args)
    elif args.command == 'ca':
        if args.ca_command == 'list-certs':
            return cmd_ca_list_certs(args)
        elif args.ca_command == 'show-cert':
            return cmd_ca_show_cert(args)
    elif args.ca_command == 'revoke':
        return cmd_ca_revoke(args)
    elif args.ca_command == 'gen-crl':
        return cmd_ca_gen_crl(args)
    elif args.ca_command == 'check-revoked':
        return cmd_ca_check_revoked(args)
    elif args.command == 'ca':
        if args.ca_command == 'issue-ocsp-cert':
            return cmd_ca_issue_ocsp_cert(args)
    elif args.command == 'ocsp':
        if args.ocsp_command == 'serve':
            return cmd_ocsp_serve(args)
    elif args.config:
        global _config
        _config = MicroPKIConfig(args.config)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
