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
    parser = subparsers.add_parser(
        'serve',
        help='Start repository HTTP server',
        description='Start HTTP server for certificate distribution'
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='Bind address (default: 127.0.0.1)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8080,
        help='TCP port (default: 8080)'
    )

    parser.add_argument(
        '--db-path',
        default='./pki/micropki.db',
        help='Path to SQLite database (default: ./pki/micropki.db)'
    )

    parser.add_argument(
        '--cert-dir',
        default='./pki/certs',
        help='Directory containing PEM certificates (default: ./pki/certs)'
    )

    parser.add_argument(
        '--log-file',
        help='Optional path to log file'
    )

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
            logger = setup_logger("micropki.repo", args.log_file)

        server = RepositoryServer(
            db_path=args.db_path,
            cert_dir=args.cert_dir,
            host=args.host,
            port=args.port
        )

        print(f"Starting repository server on {args.host}:{args.port}")
        print(f"Database: {args.db_path}")
        print(f"Certificate directory: {args.cert_dir}")
        print("Press Ctrl+C to stop")

        server.start()

        return 0

    except KeyboardInterrupt:
        print("\nServer stopped")
        return 0
    except Exception as e:
        print(f"Error starting server: {str(e)}", file=sys.stderr)
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
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
