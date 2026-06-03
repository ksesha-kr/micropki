# MicroPKI API Reference

## CLI Commands

### CA Commands

#### `micropki ca init`

Initialize a self-signed Root CA.

```bash
micropki ca init --subject <DN> --passphrase-file <file> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--subject` | Distinguished Name (e.g., `/CN=Root CA`) | Required |
| `--key-type` | `rsa` or `ecc` | `rsa` |
| `--key-size` | Key size (RSA: 4096, ECC: 384) | `4096` |
| `--passphrase-file` | File with passphrase for key encryption | Required |
| `--out-dir` | Output directory | `./pki` |
| `--validity-days` | Validity period in days | `3650` |
| `--log-file` | Path to log file | stderr |
| `--force` | Overwrite existing files | `False` |

#### `micropki ca issue-intermediate`

Create an Intermediate CA signed by Root CA.

```bash
micropki ca issue-intermediate --root-cert <file> --root-key <file> --root-pass-file <file> --subject <DN> --passphrase-file <file> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--root-cert` | Root CA certificate (PEM) | Required |
| `--root-key` | Root CA private key (PEM) | Required |
| `--root-pass-file` | Root CA passphrase file | Required |
| `--subject` | Intermediate CA DN | Required |
| `--key-type` | `rsa` or `ecc` | `rsa` |
| `--key-size` | Key size | `4096` |
| `--passphrase-file` | Intermediate CA passphrase | Required |
| `--out-dir` | Output directory | `./pki` |
| `--validity-days` | Validity period | `1825` |
| `--pathlen` | Path length constraint | `0` |

#### `micropki ca issue-cert`

Issue an end-entity certificate.

```bash
micropki ca issue-cert --ca-cert <file> --ca-key <file> --ca-pass-file <file> --template <type> --subject <DN> [options]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--ca-cert` | Issuer CA certificate | Required |
| `--ca-key` | Issuer CA private key | Required |
| `--ca-pass-file` | Issuer CA passphrase | Required |
| `--template` | `server`, `client`, or `code_signing` | Required |
| `--subject` | Subject DN | Required |
| `--san` | Subject Alternative Name (repeatable) | None |
| `--out-dir` | Output directory | `./pki/certs` |
| `--validity-days` | Validity period | `365` |
| `--csr` | External CSR file | None |

#### `micropki ca revoke`

Revoke a certificate by serial number.

```bash
micropki ca revoke <serial> [--reason <code>] [--force]
```

| Option | Description | Default |
|--------|-------------|---------|
| `serial` | Certificate serial number (hex) | Required |
| `--reason` | Revocation reason | `unspecified` |
| `--force` | Skip confirmation | `False` |

Supported reasons: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`

#### `micropki ca gen-crl`

Generate Certificate Revocation List.

```bash
micropki ca gen-crl --ca <root|intermediate> [--next-update <days>] [--out-file <path>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--ca` | CA type: `root` or `intermediate` | Required |
| `--next-update` | Days until next CRL update | `7` |
| `--out-file` | Custom output path | Auto-generated |

#### `micropki ca compromise`

Simulate private key compromise.

```bash
micropki ca compromise --cert <file> [--reason <code>] [--force]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--cert` | Certificate file path | Required |
| `--reason` | Reason code | `keyCompromise` |
| `--force` | Skip confirmation | `False` |

### Client Commands

#### `micropki client gen-csr`

Generate private key and CSR.

```bash
micropki client gen-csr --subject <DN> [--key-type <type>] [--key-size <size>] [--san <value>] [--out-key <file>] [--out-csr <file>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--subject` | Subject DN | Required |
| `--key-type` | `rsa` or `ecc` | `rsa` |
| `--key-size` | Key size | `2048` |
| `--san` | Subject Alternative Name | None |
| `--out-key` | Private key output | `./key.pem` |
| `--out-csr` | CSR output | `./request.csr.pem` |

#### `micropki client request-cert`

Submit CSR and retrieve certificate.

```bash
micropki client request-cert --csr <file> --template <type> --ca-url <url> [--out-cert <file>] [--api-key <key>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--csr` | CSR file path | Required |
| `--template` | Certificate template | Required |
| `--ca-url` | Repository base URL | Required |
| `--out-cert` | Output certificate | `./cert.pem` |
| `--api-key` | API authentication key | None |

#### `micropki client validate`

Validate certificate chain.

```bash
micropki client validate --cert <file> --untrusted <file> --trusted <file> [--format <format>] [--validation-time <time>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--cert` | Leaf certificate | Required |
| `--untrusted` | Intermediate certificate(s) | Required |
| `--trusted` | Root CA certificate | `./pki/certs/ca.cert.pem` |
| `--format` | `text` or `json` | `text` |
| `--validation-time` | ISO 8601 timestamp | Current time |

### Repository Server Commands

#### `micropki repo serve`

Start HTTP repository server.

```bash
micropki repo serve [--host <addr>] [--port <port>] [--db-path <path>] [--cert-dir <dir>] [--rate-limit <n>] [--rate-burst <n>] [--enable-ocsp] [--ocsp-responder-cert <file>] [--ocsp-responder-key <file>] [--ocsp-ca-cert <file>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--host` | Bind address | `127.0.0.1` |
| `--port` | TCP port | `8080` |
| `--db-path` | Database path | `./pki/micropki.db` |
| `--cert-dir` | Certificate directory | `./pki/certs` |
| `--rate-limit` | Requests per second | `0` (disabled) |
| `--rate-burst` | Burst allowance | `10` |
| `--enable-ocsp` | Enable OCSP endpoint | `False` |
| `--log-file` | Log file path | stderr |

### OCSP Responder Commands

#### `micropki ocsp serve`

Start OCSP responder server.

```bash
micropki ocsp serve --responder-cert <file> --responder-key <file> --ca-cert <file> [--host <addr>] [--port <port>] [--db-path <path>] [--cache-ttl <sec>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--responder-cert` | OCSP signing certificate | Required |
| `--responder-key` | OCSP private key | Required |
| `--ca-cert` | Issuer CA certificate | Required |
| `--host` | Bind address | `127.0.0.1` |
| `--port` | TCP port | `8081` |
| `--db-path` | Database path | `./pki/micropki.db` |
| `--cache-ttl` | Response cache TTL (seconds) | `60` |

### Audit Commands

#### `micropki audit query`

Query audit logs.

```bash
micropki audit query [--from <timestamp>] [--to <timestamp>] [--level <level>] [--operation <op>] [--serial <hex>] [--format <format>] [--verify]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--from` | Start timestamp (ISO 8601) | None |
| `--to` | End timestamp (ISO 8601) | None |
| `--level` | `INFO`, `WARNING`, `ERROR`, `AUDIT` | None |
| `--operation` | Operation type filter | None |
| `--serial` | Certificate serial filter | None |
| `--format` | `table`, `json`, `csv` | `table` |
| `--verify` | Verify hash chain integrity | `False` |

#### `micropki audit verify`

Verify audit log integrity.

```bash
micropki audit verify [--log-file <path>] [--chain-file <path>]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--log-file` | Audit log path | `./pki/audit/audit.log` |
| `--chain-file` | Chain file path | `./pki/audit/chain.dat` |

#### `micropki audit ct-verify`

Check if certificate exists in CT log.

```bash
micropki audit ct-verify --serial <hex>
```

| Option | Description | Default |
|--------|-------------|---------|
| `--serial` | Certificate serial number | Required |

## HTTP API Endpoints

### `GET /certificate/<serial>`

Retrieve certificate by serial number.

**Response:** `200 OK` with PEM certificate (Content-Type: `application/x-pem-file`)

**Errors:**
- `400 Bad Request` - Invalid serial number format
- `404 Not Found` - Certificate not found

### `GET /ca/root`

Get Root CA certificate.

**Response:** `200 OK` with PEM certificate

**Errors:** `404 Not Found`

### `GET /ca/intermediate`

Get Intermediate CA certificate.

**Response:** `200 OK` with PEM certificate

**Errors:** `404 Not Found`

### `GET /crl?ca=<root|intermediate>`

Get CRL for specified CA.

**Response:** `200 OK` with DER CRL (Content-Type: `application/pkix-crl`)

**Errors:**
- `400 Bad Request` - Invalid CA type
- `404 Not Found` - CRL not found

### `POST /ocsp`

OCSP request (RFC 6960).

**Request:** DER-encoded OCSP request (Content-Type: `application/ocsp-request`)

**Response:** `200 OK` with DER-encoded OCSP response (Content-Type: `application/ocsp-response`)

### `POST /request-cert?template=<type>`

Submit CSR for certificate issuance.

**Request:** PEM-encoded CSR (Content-Type: `application/x-pem-file`)

**Response:** `201 Created` with PEM certificate

**Headers:** `X-API-Key: changeme` (optional authentication)

### `GET /health`

Health check endpoint.

**Response:** `200 OK` with JSON `{"status": "ok", "timestamp": "..."}`

## Database Schema

### certificates table

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    cert_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    revocation_reason TEXT,
    revocation_date TEXT,
    created_at TEXT NOT NULL
);
```

### crl_metadata table

```sql
CREATE TABLE crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL UNIQUE,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);
```

### compromised_keys table

```sql
CREATE TABLE compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL
);
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Policy violation |
| `3` | Database error |
| `4` | Cryptographic error |
```
