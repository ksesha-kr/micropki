set -e

SERVER_CERT="${1:-./pki/certs/example.com.cert.pem}"
SERVER_KEY="${2:-./pki/certs/example.com.key.pem}"
ROOT_CERT="${3:-./pki/certs/ca.cert.pem}"
PORT="${4:-8443}"

echo "=== MicroPKI TLS Handshake Test ==="
echo "Server certificate: $SERVER_CERT"
echo "Server key: $SERVER_KEY"
echo "Root CA: $ROOT_CERT"
echo "Port: $PORT"
echo

for file in "$SERVER_CERT" "$SERVER_KEY" "$ROOT_CERT"; do
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        exit 1
    fi
done

echo "Starting test server on port $PORT..."
openssl s_server \
    -cert "$SERVER_CERT" \
    -key "$SERVER_KEY" \
    -CAfile "$ROOT_CERT" \
    -port "$PORT" \
    -www \
    -verify_return_error \
    -Verify 1 \
    > /dev/null 2>&1 &
SERVER_PID=$!

sleep 2

echo "Testing client connection..."
if openssl s_client \
    -connect "localhost:$PORT" \
    -CAfile "$ROOT_CERT" \
    -verify_return_error \
    -verify_hostname "example.com" \
    < /dev/null 2>/dev/null | grep -q "Verification: OK"; then
    echo "TLS handshake successful!"
    RESULT=0
else
    echo "TLS handshake failed!"
    RESULT=1
fi

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

exit $RESULT