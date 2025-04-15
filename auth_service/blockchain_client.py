# auth_service/blockchain_client.py
import requests
import os
import logging

log = logging.getLogger(__name__)

# Get blockchain node service URL from environment variable
# Default uses K8s internal DNS: http://<service-name>.<namespace>.svc.cluster.local:<port>
BLOCKCHAIN_NODE_SERVICE_URL = os.getenv("BLOCKCHAIN_NODE_SVC_URL", "http://blockchain-node-svc.qr-auth.svc.cluster.local:5000")
REQUEST_TIMEOUT = 5 # Seconds

def get_identity_pubkey(identity: str) -> str | None:
    """Fetches the public key for an identity from a blockchain node."""
    if not identity:
        return None

    url = f"{BLOCKCHAIN_NODE_SERVICE_URL}/get_public_key"
    params = {"identity": identity}
    try:
        response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        data = response.json()
        pub_key = data.get("public_key_hex")
        if pub_key:
            log.debug(f"Successfully retrieved public key for identity: {identity}")
            return pub_key
        else:
            log.warning(f"Public key not found in response for identity: {identity}")
            return None

    except requests.exceptions.Timeout:
        log.error(f"Timeout connecting to blockchain node at {url} for identity {identity}")
        return None
    except requests.exceptions.ConnectionError:
         log.error(f"Connection error to blockchain node at {url} for identity {identity}")
         return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            log.info(f"Identity not found on blockchain: {identity}")
        else:
            log.error(f"HTTP error fetching public key for {identity} from {url}: {e.response.status_code} {e.response.text[:100]}")
        return None
    except requests.exceptions.RequestException as e:
        log.error(f"Error connecting to blockchain node at {url} for identity {identity}: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error fetching public key for {identity}: {e}")
        return None

def register_identity_on_blockchain(identity: str, public_key_hex: str) -> bool:
    """Tells a blockchain node to register an identity (simple proxy)."""
    if not identity or not public_key_hex:
        return False

    url = f"{BLOCKCHAIN_NODE_SERVICE_URL}/register"
    payload = {"identity": identity, "public_key_hex": public_key_hex}
    try:
        response = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        log.info(f"Successfully proxied registration for identity: {identity}")
        return True
    except requests.exceptions.Timeout:
        log.error(f"Timeout connecting to blockchain node at {url} for registration {identity}")
        return False
    except requests.exceptions.ConnectionError:
         log.error(f"Connection error to blockchain node at {url} for registration {identity}")
         return False
    except requests.exceptions.HTTPError as e:
        log.error(f"HTTP error during registration for {identity} at {url}: {e.response.status_code} {e.response.text[:100]}")
        return False
    except requests.exceptions.RequestException as e:
        log.error(f"Error connecting to blockchain node at {url} for registration {identity}: {e}")
        return False
    except Exception as e:
        log.error(f"Unexpected error during registration for {identity}: {e}")
        return False