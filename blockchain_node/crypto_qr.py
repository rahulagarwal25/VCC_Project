# blockchain_node/crypto_qr.py
# Conceptual - Requires installing and using the actual liboqs library bindings
import oqs # Assuming oqs python wrapper is installed and working
import logging
import os

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

# Use a specific PQC algorithm supported by liboqs, e.g., Dilithium
# Choose one available in your installed liboqs version
KEY_MECHANISM = os.environ.get("QR_KEY_MECHANISM", "Dilithium3") # Example, make configurable if needed

log.info(f"Using QR Key Mechanism: {KEY_MECHANISM}")

# --- Singleton pattern for OQS KEM/SIG instances ---
# Avoid reinitializing OQS mechanisms repeatedly if possible
_signers = {}
_verifiers = {}

def get_signer():
    """Gets a reusable signer instance for the node."""
    # Note: In a real app, the private key needs careful, persistent management.
    # Here, we generate on startup for simplicity.
    if KEY_MECHANISM not in _signers:
        try:
            log.info(f"Initializing OQS Signature signer for {KEY_MECHANISM}")
            signer = oqs.Signature(KEY_MECHANISM)
            public_key = signer.generate_keypair()
            # Store the signer object (which holds the secret key)
            _signers[KEY_MECHANISM] = (public_key, signer)
            log.info(f"Generated Node QR Keypair. Public Key Length: {len(public_key)}")
        except oqs.MechanismNotEnabledError:
            log.error(f"OQS Key Mechanism '{KEY_MECHANISM}' is not enabled/supported in liboqs build!")
            raise
        except Exception as e:
             log.error(f"Failed to initialize OQS signer: {e}")
             raise
    return _signers[KEY_MECHANISM] # Returns (public_key_bytes, signer_object)

def get_verifier():
    """Gets a reusable verifier instance."""
    if KEY_MECHANISM not in _verifiers:
        try:
            log.info(f"Initializing OQS Signature verifier for {KEY_MECHANISM}")
            _verifiers[KEY_MECHANISM] = oqs.Signature(KEY_MECHANISM)
        except oqs.MechanismNotEnabledError:
            log.error(f"OQS Key Mechanism '{KEY_MECHANISM}' is not enabled/supported in liboqs build!")
            raise
        except Exception as e:
             log.error(f"Failed to initialize OQS verifier: {e}")
             raise
    return _verifiers[KEY_MECHANISM]


def generate_qr_keypair_external():
    """Generates a new QR keypair for external use (e.g., user registration)."""
    # This generates a *new* keypair each time, intended for users, not the node's identity.
    try:
        signer = oqs.Signature(KEY_MECHANISM)
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key() # Export for the user to save
        log.info(f"Generated external QR Keypair. Public Key Length: {len(public_key)}")
        # Return hex encoded keys for easier transport/storage in demo
        return public_key.hex(), secret_key.hex()
    except Exception as e:
        log.error(f"Failed to generate external QR keypair: {e}")
        return None, None

def sign_message(signer_object, message: bytes) -> bytes | None:
    """Signs a message using the QR private key associated with the signer object."""
    if not signer_object or not isinstance(message, bytes):
        log.error("Invalid arguments for sign_message")
        return None
    try:
        signature = signer_object.sign(message)
        log.debug(f"Signed message ({len(message)} bytes). Signature length: {len(signature)}")
        return signature
    except Exception as e:
        log.error(f"Failed to sign message: {e}")
        return None

def verify_signature(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    """Verifies a signature using the QR public key."""
    if not public_key_hex or not isinstance(message, bytes) or not isinstance(signature, bytes):
        log.error("Invalid arguments for verify_signature")
        return False

    verifier = get_verifier()
    if not verifier:
        return False

    try:
        public_key = bytes.fromhex(public_key_hex)
        is_valid = verifier.verify(message, signature, public_key)
        log.debug(f"Signature verification result: {is_valid}")
        return is_valid
    except ValueError:
         log.error("Invalid public key hex format.")
         return False
    except Exception as e:
        # Catch potential errors during verification (e.g., malformed signature)
        log.error(f"Verification failed with exception: {e}")
        return False

# --- Example Usage (Conceptual - usually called from main app) ---
# if __name__ == "__main__":
#     # Test node's internal key
#     node_pub_key, node_signer = get_signer()
#     if node_signer:
#         msg = b"Test message for node signing"
#         sig = sign_message(node_signer, msg)
#         if sig:
#             is_ok = verify_signature(node_pub_key.hex(), msg, sig)
#             print(f"Node self-signature verification successful: {is_ok}")
#         else:
#             print("Failed to sign message with node key.")
#     else:
#         print("Failed to get node signer.")

#     # Test external key generation
#     ext_pub, ext_sec = generate_qr_keypair_external()
#     if ext_pub and ext_sec:
#         print(f"External Pub Key (Hex): {ext_pub[:20]}...")
#         # In a real scenario, ext_sec would be saved securely by the user
#         # To test verification, one would need to load the secret key back into a signer
#         # This requires careful handling omitted here for brevity.
#     else:
#         print("Failed to generate external keypair.")