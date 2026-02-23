set -e

CERT_FILE="${1:-./pki/certs/ca.cert.pem}"

echo "=== MicroPKI OpenSSL Verification ==="
echo "Certificate: $CERT_FILE"
echo

if [ ! -f "$CERT_FILE" ]; then
    echo "Certificate file not found: $CERT_FILE"
    exit 1
fi

echo "=== Certificate Information ==="
openssl x509 -in "$CERT_FILE" -text -noout | head -20
echo "..."

echo -e "\n=== Basic Constraints ==="
openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "X509v3 Basic Constraints"

echo -e "\n=== Key Usage ==="
openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "X509v3 Key Usage"

echo -e "\n=== Self-Signed Verification ==="
if openssl verify -CAfile "$CERT_FILE" "$CERT_FILE" > /dev/null 2>&1; then
    echo "Certificate self-verification passed"
else
    echo "Certificate self-verification failed"
    openssl verify -CAfile "$CERT_FILE" "$CERT_FILE"
    exit 1
fi

echo -e "\n=== Key Information ==="
if openssl x509 -in "$CERT_FILE" -text -noout | grep -q "RSA"; then
    echo "RSA key detected"
    MODULUS=$(openssl x509 -in "$CERT_FILE" -modulus -noout)
    echo "Modulus: ${MODULUS:0:50}..."
elif openssl x509 -in "$CERT_FILE" -text -noout | grep -q "ECDSA"; then
    echo "ECC key detected"
    openssl x509 -in "$CERT_FILE" -text -noout | grep -A2 "Public Key Algorithm"
fi

echo -e "\nAll OpenSSL verification tests passed!"