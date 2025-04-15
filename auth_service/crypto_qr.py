# auth_service/crypto_qr.py
# This file is identical to blockchain_node/crypto_qr.py
# In a larger project, this could be a shared library/package.

import logging
import os

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)
logger = logging.getLogger("crypto_qr")

KEY_MECHANISM = os.environ.get("QR_KEY_MECHANISM", "Dilithium3")
log.info(f"Auth Service Using QR Key Mechanism: {KEY_MECHANISM}")



def get_signer():
    mechanism = os.environ.get("QR_KEY_MECHANISM", "Dilithium3")
    log.info(f"Initializing signer with mechanism: {mechanism}")
    try:
        signer = oqs.Signature(mechanism)
        return signer.generate_keypair()
    except Exception as e:
        log.error(f"Error initializing OQS signer for {mechanism}: {e}")
        raise

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
    """Generates a new QR keypair (e.g., for a user)."""
    try:
        signer = oqs.Signature(KEY_MECHANISM)
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        log.info(f"Generated external QR Keypair. Public Key Length: {len(public_key)}")
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
        log.error(f"Verification failed with exception: {e}")
        return False

# Initialize the auth service's own signer on load
auth_service_pub_key_bytes, auth_service_signer_obj = get_signer()
if auth_service_signer_obj:
    auth_service_pub_key_hex = auth_service_pub_key_bytes.hex()
    log.info(f"Auth Service Initialized. Own Public Key: {auth_service_pub_key_hex[:15]}...")
else:
     log.error("CRITICAL: Auth Service failed to initialize its own QR keys.")
     auth_service_pub_key_hex = None