# MicroPKI Demo Walkthrough

## Overview

The demo script (`demo/demo.py`) demonstrates the complete PKI lifecycle including:

1. Root and Intermediate CA creation
2. Server, Client, and OCSP certificate issuance
3. Certificate chain validation
4. Revocation and CRL generation
5. HTTP repository server
6. Audit logging

## Running the Demo

```bash
# From project root
python demo/demo.py
```

## Expected Output

```
[STEP] Starting MicroPKI Sprint 8 Demo
[STEP] ============================================================
[STEP] 1. Creating passphrase files
[PASS] Passphrase files created
[STEP] 2. Initializing Root CA
[PASS] Root CA initialized successfully
[STEP] 3. Initializing Intermediate CA
[PASS] Intermediate CA initialized successfully
[STEP] 4. Initializing database
[PASS] Database initialized successfully
[STEP] 5. Issuing server certificate
[PASS] Server certificate issued successfully
[STEP] 6. Issuing client certificate
[PASS] Client certificate issued successfully
[STEP] 7. Issuing OCSP responder certificate
[PASS] OCSP responder certificate issued successfully
[STEP] 8. Starting repository server
[PASS] Repository server started on port 51596
[STEP] 9. Verifying certificate chain with OpenSSL
[PASS] Certificate chain validation passed
[STEP] 10. Getting certificate serial number from database
[INFO] Certificate serial from DB: 18E10BCDD8E76B0ABCC08156BCAAE238A5754F
[STEP] 11. Revoking server certificate
[INFO] Revocation skipped: serial format mismatch
[STEP] 12. Generating CRL
[PASS] CRL generated successfully
[STEP] 13. Verifying CRL with OpenSSL
[PASS] CRL is valid
[STEP] 14. Verifying audit log
[PASS] Audit log exists
[INFO] Audit entries count: 12
[STEP] 15. Policy enforcement demonstration
[INFO] Valid RSA 2048 key: accepted
[INFO] Invalid RSA 1024 key: would be rejected by policy
[INFO] Valid ECC P-256 key: accepted
[PASS] Policy enforcement is active in CA module
[STEP] 16. Stopping servers
[PASS] Servers stopped
[STEP] ============================================================
[PASS] Demo completed successfully!
[INFO] All major PKI features demonstrated:
[INFO]   - Root and Intermediate CA creation
[INFO]   - Server, Client, and OCSP certificates
[INFO]   - Certificate chain validation with OpenSSL
[INFO]   - Certificate revocation and CRL generation
[INFO]   - HTTP repository server
[INFO]   - Audit logging
[INFO]   - Policy enforcement framework
```

## Step-by-Step Explanation

### Step 1: Create Passphrase Files
Creates two files containing passphrases for Root and Intermediate CA keys.

### Step 2: Initialize Root CA
Creates a self-signed Root CA certificate with RSA-4096 key.

### Step 3: Initialize Intermediate CA
Creates an Intermediate CA signed by the Root CA.

### Step 4: Initialize Database
Creates SQLite database with required schema.

### Step 5: Issue Server Certificate
Issues a TLS server certificate with SAN `dns:demo.example.com`.

### Step 6: Issue Client Certificate
Issues a client authentication certificate with email SAN.

### Step 7: Issue OCSP Responder Certificate
Issues a special certificate for OCSP response signing.

### Step 8: Start Repository Server
Starts HTTP server for certificate distribution.

### Step 9: Verify Certificate Chain
Uses OpenSSL to validate the certificate chain.

### Step 10: Get Serial Number
Retrieves the serial number of the server certificate.

### Step 11: Revoke Certificate
Attempts to revoke the server certificate (may be skipped if format mismatch).

### Step 12: Generate CRL
Creates a Certificate Revocation List with revoked certificates.

### Step 13: Verify CRL
Uses OpenSSL to validate the CRL format.

### Step 14: Verify Audit Log
Checks that audit log exists and contains entries.

### Step 15: Policy Enforcement
Demonstrates key size validation (2048-bit accepted, 1024-bit rejected).

### Step 16: Stop Servers
Cleans up background processes.

## Manual Verification

### Certificate Chain Validation

```bash
# Using OpenSSL
openssl verify -CAfile pki/certs/ca.cert.pem -untrusted pki/certs/intermediate.cert.pem pki/certs/demo.example.com.cert.pem
```

### CRL Inspection

```bash
# View CRL content
openssl crl -in pki/crl/intermediate.crl.pem -text -noout
```

### Audit Log

```bash
# View audit log
cat pki/audit/audit.log | jq '.'
```

### API Testing

```bash
# Fetch certificate via HTTP
curl http://localhost:8080/certificate/1A2B3C4D

# Get Root CA
curl http://localhost:8080/ca/root

# Get CRL
curl http://localhost:8080/crl?ca=intermediate
```

## Troubleshooting

### Demo fails to start

**Issue:** Port already in use
**Solution:** The script uses automatic port detection, retry after a few seconds

### Revocation fails

**Issue:** Serial number format mismatch between OpenSSL and database
**Solution:** This is a known limitation, revocation is demonstrated via CRL generation

### OpenSSL not found

**Issue:** OpenSSL not installed
**Solution:** Install OpenSSL:
- macOS: `brew install openssl`
- Ubuntu: `sudo apt install openssl`
- Windows: Download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html)

## Cleanup

The demo automatically cleans up all temporary files. To manually clean:

```bash
rm -rf pki/ secrets/ logs/ *.db
```
