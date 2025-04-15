#!/usr/bin/env python3
import requests
import time
import sys
import os
import logging

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format='%(asctime)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)

# --- Configuration ---
# Get the Internal Load Balancer IP for the auth service
# Option 1: Hardcode after deployment (kubectl get svc auth-service-internal-lb -n qr-auth -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
# Option 2: Pass as environment variable
AUTH_SERVICE_IP = os.getenv("AUTH_SERVICE_IP")
if not AUTH_SERVICE_IP:
    log.error("ERROR: AUTH_SERVICE_IP environment variable not set.")
    log.error("Run: export AUTH_SERVICE_IP=$(kubectl get svc auth-service-internal-lb -n qr-auth -o jsonpath='{.status.loadBalancer.ingress[0].ip}')")
    sys.exit(1)

AUTH_SERVICE_URL = f"http://{AUTH_SERVICE_IP}:80" # ILB listens on port 80

# For generating keys via API (INSECURE - DEMO ONLY)
# You need to reach a *blockchain node* pod for this specific endpoint in the demo code.
# Easiest way for testing is kubectl port-forward:
# kubectl port-forward statefulset/blockchain-node 5000:5000 -n qr-auth
# Then use:
BLOCKCHAIN_NODE_PF_URL = "http://localhost:5000" # Use if port-forwarding

# --- OQS Dependency ---
# This client script ALSO needs oqs-python installed to perform signing
try:
    import oqs
except ImportError:
    log.error("ERROR: oqs-python library not found.")
    log.error("Please install it: pip install oqs")
    log.error("(This might require system dependencies like cmake, ninja, gcc, libssl-dev)")
    sys.exit(1)

KEY_MECHANISM = os.environ.get("QR_KEY_MECHANISM", "Dilithium3") # Must match server
log.info(f"Using QR Key Mechanism: {KEY_MECHANISM}")


# --- Helper Functions ---

def generate_new_qr_keys_via_api(node_url=BLOCKCHAIN_NODE_PF_URL):
    """Generates keys using the blockchain node's insecure API endpoint (DEMO ONLY)."""
    url = f"{node_url}/generate_keys"
    log.info(f"Requesting new QR keys from {url}...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        pub_key = data.get("public_key_hex")
        # !!! Retrieving secret key via API is highly insecure !!!
        sec_key = data.get("secret_key_hex")
        if pub_key and sec_key:
            log.info("Successfully generated keys via API (Insecure Demo Method).")
            return pub_key, sec_key
        else:
            log.error(f"API response missing keys: {data}")
            return None, None
    except Exception as e:
        log.error(f"Error generating keys via API: {e}")
        return None, None

def generate_new_qr_keys_local():
    """Generates QR keys locally using oqs-python."""
    log.info(f"Generating new QR keypair locally using {KEY_MECHANISM}...")
    try:
        signer = oqs.Signature(KEY_MECHANISM)
        public_key_bytes = signer.generate_keypair()
        secret_key_bytes = signer.export_secret_key()
        log.info("Successfully generated keys locally.")
        # Return hex for consistency with API methods
        return public_key_bytes.hex(), secret_key_bytes.hex()
    except Exception as e:
        log.error(f"Error generating keys locally: {e}")
        return None, None

def sign_message_local(secret_key_hex: str, message: str) -> str | None:
    """Signs a message locally using the provided secret key hex."""
    log.debug(f"Signing message: '{message}'")
    if not secret_key_hex or not message:
        return None
    try:
        signer = oqs.Signature(KEY_MECHANISM)
        secret_key_bytes = bytes.fromhex(secret_key_hex)
        # Import the secret key into the signer object
        signer.import_secret_key(secret_key_bytes)

        message_bytes = message.encode('utf-8')
        signature_bytes = signer.sign(message_bytes)
        log.debug("Message signed successfully.")
        return signature_bytes.hex()
    except ValueError:
        log.error("Invalid secret key hex format.")
        return None
    except Exception as e:
        log.error(f"Error signing message: {e}")
        return None

def register_identity(auth_url, identity, pub_key_hex):
    """Registers the identity via the auth service proxy endpoint."""
    url = f"{auth_url}/register_identity_proxy"
    payload = {"identity": identity, "public_key_hex": pub_key_hex}
    log.info(f"Registering identity '{identity}' via {url}...")
    try:
        response = requests.post(url, json=payload, timeout=10)
        log.debug(f"Registration Response Status: {response.status_code}")
        log.debug(f"Registration Response Body: {response.text[:200]}") # Log beginning of response
        response.raise_for_status() # Check for HTTP errors
        log.info(f"Registration request for '{identity}' accepted by auth service.")
        return True
    except requests.exceptions.RequestException as e:
        log.error(f"Error registering identity '{identity}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             log.error(f"Response status: {e.response.status_code}")
             log.error(f"Response body: {e.response.text[:200]}")
        return False
    except Exception as e:
        log.error(f"Unexpected error during registration for '{identity}': {e}")
        return False


def authenticate_identity(auth_url, identity, secret_key_hex, audience="test_resource"):
    """Authenticates the identity by sending a signed message."""
    url = f"{auth_url}/authenticate"
    # Create a message to sign (e.g., timestamp + nonce)
    message_to_sign = f"auth_request|{identity}|{int(time.time())}"
    log.info(f"Attempting authentication for '{identity}'...")
    log.debug(f"Message to sign: '{message_to_sign}'")

    signature_hex = sign_message_local(secret_key_hex, message_to_sign)
    if not signature_hex:
        log.error("Failed to sign authentication message.")
        return None

    payload = {
        "identity": identity,
        "message": message_to_sign,
        "signature_hex": signature_hex,
        "audience": audience
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        log.debug(f"Authentication Response Status: {response.status_code}")
        log.debug(f"Authentication Response Body: {response.text[:200]}")
        response.raise_for_status()
        data = response.json()
        token = data.get("token")
        if token:
            log.info(f"Authentication successful for '{identity}'. Received token.")
            return token
        else:
            log.error(f"Authentication successful but no token found in response: {data}")
            return None
    except requests.exceptions.RequestException as e:
        log.error(f"Error authenticating identity '{identity}': {e}")
        if hasattr(e, 'response') and e.response is not None:
             log.error(f"Response status: {e.response.status_code}")
             log.error(f"Response body: {e.response.text[:200]}")
        return None
    except Exception as e:
        log.error(f"Unexpected error during authentication for '{identity}': {e}")
        return None

def verify_auth_token(auth_url, token, audience="test_resource"):
    """Asks the auth service to verify the token (simulates resource provider check)."""
    url = f"{auth_url}/verify_token"
    payload = {"token": token, "audience": audience}
    log.info(f"Verifying token with audience '{audience}'...")
    try:
        response = requests.post(url, json=payload, timeout=10)
        log.debug(f"Verification Response Status: {response.status_code}")
        log.debug(f"Verification Response Body: {response.text[:200]}")
        response.raise_for_status()
        data = response.json()
        is_valid = data.get("valid", False)
        if is_valid:
            log.info(f"Token verification successful: {data}")
        else:
            log.warning(f"Token verification failed: {data}")
        return is_valid, data
    except requests.exceptions.RequestException as e:
        log.error(f"Error verifying token: {e}")
        if hasattr(e, 'response') and e.response is not None:
             log.error(f"Response status: {e.response.status_code}")
             log.error(f"Response body: {e.response.text[:200]}")
        return False, {"error": str(e)}
    except Exception as e:
         log.error(f"Unexpected error during token verification: {e}")
         return False, {"error": str(e)}


# --- Main Test Flow ---
if __name__ == "__main__":
    log.info(f"Starting QR Authentication Test Client")
    log.info(f"Target Auth Service URL: {AUTH_SERVICE_URL}")

    # 1. Generate Keys (Locally is preferred and more realistic)
    # pub_key, sec_key = generate_new_qr_keys_via_api() # Insecure demo method
    pub_key, sec_key = generate_new_qr_keys_local() # Secure local method
    if not pub_key or not sec_key:
        log.error("Failed to obtain QR keys. Exiting.")
        sys.exit(1)

    log.info(f"Generated Public Key (hex, start): {pub_key[:20]}...")
    # !!! In a real app, sec_key must be stored securely !!!

    # 2. Register Identity
    test_identity = f"test-user-{int(time.time())}" # Unique identity for testing
    if not register_identity(AUTH_SERVICE_URL, test_identity, pub_key):
        log.error(f"Failed to register identity '{test_identity}'. Exiting.")
        # Might be a transient issue, could retry.
        sys.exit(1)

    # Allow some time for registration to propagate (though it should be quick in demo)
    log.info("Waiting 5 seconds for registration to settle...")
    time.sleep(5)

    # 3. Authenticate
    target_audience = "billing-service-cloud-b"
    auth_token = authenticate_identity(AUTH_SERVICE_URL, test_identity, sec_key, audience=target_audience)
    if not auth_token:
        log.error(f"Failed to authenticate identity '{test_identity}'. Exiting.")
        sys.exit(1)

    log.info(f"Received Auth Token (Bearer): {auth_token[:20]}...{auth_token[-10:]}")

    # 4. Verify Token (Simulate Resource Provider)
    log.info("Simulating resource provider verifying the token...")
    is_valid, verification_details = verify_auth_token(AUTH_SERVICE_URL, auth_token, audience=target_audience)

    if is_valid:
        log.info("SUCCESS: Token is valid according to the auth service.")
    else:
        log.error("FAILURE: Token is invalid according to the auth service.")
        log.error(f"Details: {verification_details}")

    log.info("Test client finished.")