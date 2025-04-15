# auth_service/app.py
from flask import Flask, request, jsonify
import crypto_qr # Use the QR crypto functions
import blockchain_client # To interact with blockchain nodes
import time
import jwt # For standard JWT generation
import os
import logging
import hashlib

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

app = Flask(__name__)

# --- Configuration ---
# Use Kubernetes Secrets in production!
JWT_SECRET = os.getenv("JWT_SECRET", "DEMO_JWT_SECRET_REPLACE_ME")
if JWT_SECRET == "DEMO_JWT_SECRET_REPLACE_ME":
    log.warning("Using default insecure JWT_SECRET!")

# Get the service's own identity info (initialized in crypto_qr.py)
auth_service_pub_key_hex = crypto_qr.auth_service_pub_key_hex
auth_service_signer_obj = crypto_qr.auth_service_signer_obj


# --- API Endpoints ---
@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Authenticates a user/service based on a QR signature."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    identity = data.get('identity')
    message_str = data.get('message') # The original data that was signed (e.g., timestamp, nonce)
    signature_hex = data.get('signature_hex') # The QR signature in hex format
    audience = data.get('audience', 'default_cross_cloud_resource') # Optional: specify intended audience

    if not identity or not message_str or not signature_hex:
        log.warning(f"Authentication request missing fields: identity={bool(identity)}, message={bool(message_str)}, signature={bool(signature_hex)}")
        return jsonify({"error": "Missing 'identity', 'message', or 'signature_hex'"}), 400

    log.info(f"Authentication attempt for identity: {identity}, audience: {audience}")

    # 1. Get the registered public key from the Blockchain
    public_key_hex = blockchain_client.get_identity_pubkey(identity)
    if not public_key_hex:
        log.warning(f"Identity not found or blockchain unreachable for: {identity}")
        # Distinguish between not found (404) and blockchain error (503)?
        return jsonify({"error": "Identity not found or blockchain service unavailable"}), 404

    # 2. Verify the Quantum-Resistant signature
    try:
        message_bytes = message_str.encode('utf-8')
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
         log.warning(f"Invalid hex format for signature provided by identity: {identity}")
         return jsonify({"error": "Invalid signature format"}), 400

    is_valid = crypto_qr.verify_signature(public_key_hex, message_bytes, signature_bytes)

    if not is_valid:
        log.warning(f"Invalid signature provided by identity: {identity}")
        return jsonify({"error": "Invalid signature"}), 401 # 401 Unauthorized

    # 3. Signature is valid - Issue an authentication token (e.g., JWT)
    log.info(f"Signature verified for identity: {identity}. Issuing token.")
    try:
        # Standard JWT signing (for simplicity in demo)
        payload = {
            "sub": identity, # Subject
            "iss": "qr-auth-service", # Issuer
            "exp": time.time() + 3600, # Expires in 1 hour (use configurable value)
            "iat": time.time(), # Issued at
            "aud": audience, # Audience (intended recipient)
            # Add custom claims if needed
            "pkh": hashlib.sha256(public_key_hex.encode()).hexdigest()[:16] # Hash of pub key as claim (example)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

        # --- Alternative: QR Signed Assertion (More Complex) ---
        # assertion_payload = f"{identity}|{payload['exp']}|{audience}".encode()
        # qr_signature_bytes = crypto_qr.sign_message(auth_service_signer_obj, assertion_payload)
        # if qr_signature_bytes:
        #     qr_signed_assertion = qr_signature_bytes.hex()
        #     return jsonify({
        #         "identity": identity,
        #         "authenticated": True,
        #         "assertion_type": "qr_signed",
        #         "assertion": qr_signed_assertion,
        #         "service_pub_key": auth_service_pub_key_hex # Verifier needs this
        #     })
        # else:
        #     log.error(f"Failed to sign QR assertion for identity {identity}")
        #     return jsonify({"error": "Failed to sign assertion"}), 500
        # --- End Alternative ---

        return jsonify({"identity": identity, "authenticated": True, "token_type": "Bearer", "token": token})

    except Exception as e:
        log.error(f"Error issuing token for identity {identity}: {e}")
        return jsonify({"error": "Token issuance failed"}), 500


@app.route('/verify_token', methods=['POST'])
def verify_token():
    """Verifies a standard JWT issued by this service."""
    # This endpoint would be called by the resource provider (e.g., in Cloud B)
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    token = data.get('token')
    required_audience = data.get('audience') # Optional: Resource specifies its required audience

    if not token:
         return jsonify({"error": "Missing token"}), 400

    log.debug(f"Token verification request received. Required audience: {required_audience}")

    try:
        # Standard JWT verification
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=required_audience # Verify audience matches if provided
            # options={"require": ["exp", "iat", "sub", "iss", "aud"]} # Be strict
        )
        # Additional checks (e.g., check issuer)
        if payload.get("iss") != "qr-auth-service":
            log.warning(f"Invalid issuer in token: {payload.get('iss')}")
            raise jwt.InvalidIssuerError("Invalid token issuer")

        log.info(f"Token verified successfully for subject: {payload.get('sub')}")
        # Return relevant payload info, but not the whole thing necessarily
        return jsonify({"valid": True, "identity": payload.get("sub"), "audience": payload.get("aud")})

    except jwt.ExpiredSignatureError:
        log.info("Token verification failed: Expired signature")
        return jsonify({"valid": False, "error": "Token has expired"}), 401
    except jwt.InvalidAudienceError:
         log.warning(f"Token verification failed: Invalid audience. Expected: {required_audience}")
         return jsonify({"valid": False, "error": "Invalid token audience"}), 401
    except jwt.InvalidIssuerError:
         log.warning("Token verification failed: Invalid issuer")
         return jsonify({"valid": False, "error": "Invalid token issuer"}), 401
    except jwt.InvalidTokenError as e:
        log.warning(f"Token verification failed: Invalid token - {e}")
        return jsonify({"valid": False, "error": f"Invalid token: {e}"}), 401
    except Exception as e:
        log.error(f"Unexpected error during token verification: {e}")
        return jsonify({"valid": False, "error": "Token verification failed due to server error"}), 500

@app.route('/register_identity_proxy', methods=['POST'])
def register_identity_proxy():
    """Proxies identity registration request to the blockchain node."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    identity = data.get('identity')
    public_key_hex = data.get('public_key_hex')

    if not identity or not public_key_hex:
        return jsonify({"error": "Missing 'identity' or 'public_key_hex'"}), 400

    log.info(f"Proxying registration request for identity: {identity}")
    success = blockchain_client.register_identity_on_blockchain(identity, public_key_hex)

    if success:
        return jsonify({"message": "Registration request forwarded to blockchain node successfully."}), 202 # 202 Accepted
    else:
        return jsonify({"error": "Failed to forward registration request to blockchain node."}), 502 # 502 Bad Gateway

@app.route('/', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    # Could add checks for blockchain connectivity here
    return jsonify({"status": "OK", "service": "auth-service"}), 200


# --- Main Execution ---
if __name__ == '__main__':
    # Use Gunicorn in Docker CMD
    log.info("Starting Flask application for auth-service...")
    app.run(host='0.0.0.0', port=8080)