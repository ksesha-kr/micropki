set -e

echo "=== MicroPKI Chain Validation Test ==="

PKI_DIR="${1:-./pki}"
CLIENT_DIR="${2:-./client}"
mkdir -p "$CLIENT_DIR"

echo "1. Validating valid chain..."
if micropki client validate \
    --cert "$CLIENT_DIR/client.cert.pem" \
    --untrusted "$PKI_DIR/certs/intermediate.cert.pem" \
    --trusted "$PKI_DIR/certs/ca.cert.pem" \
    --format text; then
    echo "   Valid chain validation PASSED"
else
    echo "   Valid chain validation FAILED"
fi

echo ""
echo "2. Testing missing intermediate..."
if micropki client validate \
    --cert "$CLIENT_DIR/client.cert.pem" \
    --trusted "$PKI_DIR/certs/ca.cert.pem" \
    --format text 2>/dev/null; then
    echo "   Missing intermediate should fail"
else
    echo "   Missing intermediate correctly FAILED"
fi

echo ""
echo "3. Testing with JSON output..."
micropki client validate \
    --cert "$CLIENT_DIR/client.cert.pem" \
    --untrusted "$PKI_DIR/certs/intermediate.cert.pem" \
    --trusted "$PKI_DIR/certs/ca.cert.pem" \
    --format json | python -m json.tool

echo ""
echo "✅ Chain validation tests completed!"