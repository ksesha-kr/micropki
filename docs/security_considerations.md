# Security Considerations

## Important Warnings

MicroPKI is an **educational project** designed to demonstrate PKI concepts. It is **NOT** recommended for production use without significant hardening.

## Key Storage

### Root and Intermediate CA Keys
- **Storage:** Encrypted using PKCS#8 with AES-256-CBC and PBKDF2
- **Passphrases:** Read from files (must be protected with 0o600 permissions)
- **Risk:** Passphrase files can be leaked if not properly secured

### End-Entity Keys
- **Storage:** Unencrypted PEM files (by design for automated servers)
- **Permissions:** 0o600 (owner read/write only)
- **Warning:** The tool explicitly warns about unencrypted storage

## Network Security

### Repository Server
- **Protocol:** HTTP (no TLS by default)
- **Risk:** Certificate and CRL data can be intercepted
- **Mitigation:** Deploy behind HTTPS reverse proxy (nginx, Apache)

### OCSP Responder
- **Protocol:** HTTP (no TLS)
- **Risk:** OCSP responses can be intercepted or modified
- **Mitigation:** Deploy behind HTTPS or use built-in TLS (not implemented)

## Rate Limiting

- **Implementation:** Token bucket algorithm
- **Protection:** Basic DDoS mitigation
- **Limitation:** Not effective against distributed attacks
- **Default:** Disabled (`--rate-limit 0`)

## Audit System

### Hash Chain Integrity
- **Method:** SHA-256 chaining of NDJSON entries
- **Protection:** Detects tampering but doesn't prevent it
- **Limitation:** Log file itself is not signed

### Certificate Transparency
- **Implementation:** Simulated (plain text file, no Merkle tree)
- **Purpose:** Demonstration only
- **Limitation:** No cryptographic proofs of inclusion

## Policy Enforcement

### Key Size Requirements

| Certificate Type | RSA Minimum | ECC Minimum |
|-----------------|-------------|-------------|
| Root CA | 4096 bits | P-384 |
| Intermediate CA | 3072 bits | P-384 |
| End-Entity | 2048 bits | P-256 |

### Validity Periods

| Certificate Type | Maximum Validity |
|-----------------|------------------|
| Root CA | 10 years (3650 days) |
| Intermediate CA | 5 years (1825 days) |
| End-Entity | 1 year (365 days) |

### SAN Restrictions

| Template | Allowed SAN Types |
|----------|-------------------|
| server | dns, ip |
| client | email, dns |
| code_signing | dns, uri |

### Wildcard Certificates

- **Default:** Rejected
- **Override:** Can be enabled via configuration file (`allow_wildcards: true`)

## Compromise Simulation

### Key Compromise Detection
- **Method:** SHA-256 hash of DER-encoded public key
- **Storage:** `compromised_keys` table in database
- **Action:** Blocks future issuance using same public key

### Limitations
- **Simulation only:** Real compromise detection requires external monitoring
- **Manual trigger:** Must be explicitly invoked via `ca compromise`

## Database Security

### SQLite File
- **Location:** `./pki/micropki.db` (by default)
- **Permissions:** User read/write only
- **Risk:** No encryption at rest

### Sensitive Data
- **Stored:** Full PEM certificates (public data)
- **Not stored:** Private keys (except compromised key hashes)

## Audit Events

### Security-Sensitive Operations Logged

| Operation | Log Level |
|-----------|-----------|
| CA Initialization | AUDIT |
| Certificate Issuance | AUDIT |
| Revocation | AUDIT |
| CRL Generation | AUDIT |
| Compromise Simulation | AUDIT |
| Policy Violations | AUDIT |
| Configuration Changes | AUDIT |

## Best Practices

### For Evaluation/Demo

1. **Use temporary directories** for testing (`tempfile.TemporaryDirectory()`)
2. **Never commit** `pki/`, `secrets/`, or `*.db` files
3. **Set strong passphrases** for CA keys
4. **Use `--force` with caution** (skips confirmation prompts)

### For Production (Not Recommended)

If you must use MicroPKI in production:

1. **Deploy behind HTTPS** reverse proxy (nginx with TLS)
2. **Restrict network access** to repository and OCSP ports
3. **Implement additional authentication** for `/request-cert` endpoint
4. **Enable rate limiting** (`--rate-limit 10 --rate-burst 20`)
5. **Regular audit verification** (`micropki audit verify`)
6. **Secure passphrase files** (`chmod 600 secrets/*.pass`)
7. **Use dedicated database** (not SQLite for high concurrency)

## Reporting Security Issues

For security vulnerabilities, please contact the project maintainers directly.

## Disclaimer

**MICROPKI IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** The authors are not responsible for any damages arising from its use. This software is for educational purposes only.
```
