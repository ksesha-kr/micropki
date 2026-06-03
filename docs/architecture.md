# MicroPKI Architecture

## System Overview

MicroPKI is a complete Public Key Infrastructure (PKI) implementation that provides certificate management, revocation, OCSP, and audit logging capabilities.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              MicroPKI System Architecture                            │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   CLI       │    │    CA       │    │  Database   │    │   Audit     │          │
│  │  Commands   │───▶│  Modules    │───▶│  (SQLite)   │───▶│   Logger    │          │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                  │                  │                  │                 │
│         ▼                  ▼                  ▼                  ▼                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐          │
│  │   Client    │    │ Repository  │    │    CRL      │    │    CT       │          │
│  │   Tools     │    │   Server    │    │  Generator  │    │    Log      │          │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘          │
│         │                  │                  │                                     │
│         └──────────────────┼──────────────────┘                                     │
│                            ▼                                                        │
│                    ┌─────────────┐                                                 │
│                    │    OCSP     │                                                 │
│                    │  Responder  │                                                 │
│                    └─────────────┘                                                 │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Component Description

### 1. CLI Commands (`cli.py`)

Entry point for all user interactions. Provides subcommands for:
- Certificate Authority operations (`ca`)
- Client tools (`client`)
- Repository server (`repo`)
- OCSP responder (`ocsp`)
- Database management (`db`)
- Chain validation (`chain`)
- Audit queries (`audit`)

### 2. CA Modules (`ca.py`, `certificates.py`, `csr.py`)

Core PKI functionality:
- Root CA initialization and self-signed certificate generation
- Intermediate CA creation and signing
- End-entity certificate issuance with templates
- CSR generation and processing

### 3. Database Layer (`database.py`)

SQLite-based storage for:
- Issued certificates with serial numbers
- Revocation status and reasons
- CRL metadata
- Compromised keys tracking
- Certificate Transparency log

### 4. Repository Server (`repository.py`)

HTTP REST API for certificate distribution:
- `GET /certificate/<serial>` - retrieve certificate by serial
- `GET /ca/root` - get Root CA certificate
- `GET /ca/intermediate` - get Intermediate CA certificate
- `GET /crl` - get Certificate Revocation List
- `POST /ocsp` - OCSP requests
- `POST /request-cert` - submit CSR for issuance

### 5. OCSP Responder (`ocsp_responder.py`)

RFC 6960 compliant OCSP responder:
- Real-time certificate status checking
- Nonce-based replay protection
- Response caching for performance
- Multiple issuer support

### 6. CRL Generator (`crl.py`)

RFC 5280 compliant Certificate Revocation List generation:
- Version 2 CRL format
- CRL Number extension
- Reason codes for revoked certificates

### 7. Audit Logger (`audit.py`)

Cryptographically protected audit logging:
- NDJSON format with SHA-256 hash chaining
- Tamper detection
- Certificate Transparency simulation

### 8. Policy Enforcer (`policy.py`)

Security policy enforcement:
- Key size validation (RSA: 2048-4096, ECC: 256-384)
- Validity period limits
- SAN type validation per template
- Wildcard certificate controls

### 9. Client Tools (`client.py`)

End-user utilities:
- CSR generation
- Certificate request submission
- Chain validation
- Revocation status checking

## Data Flow

### Certificate Issuance Flow

```
User ──▶ CLI ──▶ CA Module ──▶ Policy Check ──▶ Certificate Generation
                                      │
                                      ▼
                              Database Storage
                                      │
                                      ▼
                              Audit Logging ──▶ CT Log
                                      │
                                      ▼
                              Repository Server
```

### Revocation Flow

```
User ──▶ CLI ──▶ Revoke Command ──▶ Database Update
                                      │
                                      ▼
                              CRL Generation
                                      │
                                      ▼
                              OCSP Responder Update
                                      │
                                      ▼
                              HTTP Distribution
```

## Security Architecture

### Key Storage

| Key Type | Storage | Encryption | Permissions |
|----------|---------|------------|-------------|
| Root CA | `pki/private/` | PKCS#8 (AES-256) | 0o600 |
| Intermediate CA | `pki/private/` | PKCS#8 (AES-256) | 0o600 |
| End-Entity | `pki/certs/` | None (warning) | 0o600 |

### Audit Integrity

Each audit entry contains:
- `prev_hash`: SHA-256 of previous entry
- `hash`: SHA-256 of current entry

This creates an immutable chain that detects tampering.

### Rate Limiting

Token bucket algorithm per client IP:
- Configurable requests per second
- Burst allowance
- HTTP 429 with Retry-After header

## Database Schema

### certificates table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| serial_hex | TEXT UNIQUE | Certificate serial number |
| subject | TEXT | Subject DN |
| issuer | TEXT | Issuer DN |
| not_before | TEXT | Validity start (ISO 8601) |
| not_after | TEXT | Validity end (ISO 8601) |
| cert_pem | TEXT | Full PEM certificate |
| status | TEXT | valid/revoked/expired |
| revocation_reason | TEXT | RFC 5280 reason code |
| revocation_date | TEXT | Revocation timestamp |

### compromised_keys table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| public_key_hash | TEXT UNIQUE | SHA-256 of public key |
| certificate_serial | TEXT | Associated certificate |
| compromise_date | TEXT | Timestamp |
| compromise_reason | TEXT | Reason code |

## Dependencies

| Component | Library | Version |
|-----------|---------|---------|
| Cryptography | cryptography | ≥3.0 |
| HTTP Server | Flask | ≥2.0 |
| CORS | flask-cors | ≥3.0 |
| HTTP Client | requests | ≥2.28 |
| Testing | pytest | ≥6.0 |
```
