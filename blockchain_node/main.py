# blockchain_node/main.py
from flask import Flask, request, jsonify
import crypto_qr # Import our QR crypto functions
import threading
import time
import os
import logging
import hashlib

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger(__name__)

app = Flask(__name__)

# --- Node State ---
# WARNING: In-memory state is lost on pod restart. Use PVs (/data mount) for real persistence.
blockchain = [] # The chain itself
identities = {} # Map identity_string -> QR_Public_Key_Hex
node_id = os.getenv("HOSTNAME", "unknown-node") # Get pod name from K8s downward API

# Initialize node's own QR identity (optional, used here for block "signing")
try:
    node_pub_key_bytes, node_signer_obj = crypto_qr.get_signer()
    node_pub_key_hex = node_pub_key_bytes.hex()
    log.info(f"Node {node_id} initialized. Public Key: {node_pub_key_hex[:15]}...")
except Exception as e:
    log.error(f"CRITICAL: Node {node_id} failed to initialize QR keys: {e}. Exiting.")
    # In K8s, the pod might restart, hopefully resolving transient issues.
    # If OQS mechanism is wrong, it will likely fail repeatedly.
    node_pub_key_hex = None
    node_signer_obj = None
    # Consider exiting or entering a degraded state
    # exit(1)


# --- Simplified Blockchain Logic ---
lock = threading.Lock() # Protect access to shared state (blockchain, identities)

def calculate_hash(block):
    """Creates a basic SHA-256 hash of a block."""
    # In a real blockchain, this would be more complex (e.g., include nonce for PoW)
    block_string = f"{block['index']}{block['timestamp']}{block['data']}{block['previous_hash']}".encode()
    return hashlib.sha256(block_string).hexdigest()

def create_genesis_block():
    """Creates the first block in the chain."""
    genesis = {"index": 0, "timestamp": time.time(), "data": "Genesis Block", "previous_hash": "0"}
    genesis["hash"] = calculate_hash(genesis) # Calculate initial hash
    log.info("Created Genesis Block")
    return genesis

# Initialize chain if empty
with lock:
    if not blockchain:
        blockchain.append(create_genesis_block())

def add_block(data) -> dict | None:
    """Adds a new block to the chain (simplified)."""
    if not node_signer_obj:
        log.error("Node signer not available, cannot add block.")
        return None

    with lock:
        previous_block = blockchain[-1]
        new_block = {
            "index": len(blockchain),
            "timestamp": time.time(),
            "data": data, # Transaction or event data
            "previous_hash": previous_block["hash"],
            "validator_id": node_id # Which node added this block
        }
        # Calculate the hash of the block content
        block_hash_content = f"{new_block['index']}{new_block['timestamp']}{new_block['data']}{new_block['previous_hash']}{new_block['validator_id']}".encode()
        new_block['hash'] = hashlib.sha256(block_hash_content).hexdigest() # Use standard hash for block integrity

        # Sign the calculated block hash with the node's QR key (as proof of validation)
        block_hash_bytes = bytes.fromhex(new_block['hash'])
        signature_bytes = crypto_qr.sign_message(node_signer_obj, block_hash_bytes)

        if signature_bytes:
            new_block["validator_signature_hex"] = signature_bytes.hex()
            blockchain.append(new_block)
            log.info(f"Node {node_id} added block {new_block['index']}. Prev Hash: {new_block['previous_hash'][:6]}, New Hash: {new_block['hash'][:6]}")
            # Persist blockchain to disk here if implementing persistence
            return new_block
        else:
            log.error(f"Node {node_id} failed to sign block {new_block['index']}.")
            return None


# --- API Endpoints ---
@app.route('/register', methods=['POST'])
def register_identity():
    """Registers a new identity with its QR public key."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    identity = data.get('identity')
    public_key_hex = data.get('public_key_hex')

    if not identity or not public_key_hex:
        return jsonify({"error": "Missing 'identity' or 'public_key_hex'"}), 400

    with lock:
        if identity in identities:
             log.warning(f"Registration attempt for existing identity: {identity}")
             return jsonify({"error": "Identity already registered"}), 409 # 409 Conflict

        # Store identity mapping (in memory for demo)
        identities[identity] = public_key_hex

        # Add a block representing this registration event
        block_data = {"type": "registration", "identity": identity, "public_key_hash": hashlib.sha256(public_key_hex.encode()).hexdigest()}
        new_block = add_block(block_data)

    if new_block:
        log.info(f"Registered Identity: {identity}, PubKeyHash: {block_data['public_key_hash'][:10]}...")
        return jsonify({"message": "Identity registered successfully", "block_index": new_block['index']}), 201
    else:
        # Rollback identity registration if block adding failed? Needs careful thought in real system.
        with lock:
            if identity in identities: del identities[identity] # Simple rollback for demo
        log.error(f"Failed to add registration block for identity: {identity}")
        return jsonify({"error": "Failed to record registration on blockchain"}), 500


@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    """Retrieves the public key for a given identity."""
    identity = request.args.get('identity')
    if not identity:
        return jsonify({"error": "Missing 'identity' query parameter"}), 400

    with lock:
        public_key_hex = identities.get(identity)

    if not public_key_hex:
        log.debug(f"Public key requested for unknown identity: {identity}")
        return jsonify({"error": "Identity not found"}), 404

    log.debug(f"Returning public key for identity: {identity}")
    return jsonify({"identity": identity, "public_key_hex": public_key_hex})

@app.route('/chain', methods=['GET'])
def get_chain():
    """Returns the current state of the blockchain."""
    with lock:
        chain_data = list(blockchain) # Return a copy
    log.debug(f"Returning blockchain state. Length: {len(chain_data)}")
    return jsonify({"chain": chain_data, "length": len(chain_data)})

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    """Generates a new QR key pair for external use (convenience endpoint for demo)."""
    # In a real system, key generation happens client-side.
    log.info("Received request to generate external keypair.")
    pub_key_hex, sec_key_hex = crypto_qr.generate_qr_keypair_external()
    if pub_key_hex and sec_key_hex:
        log.info("Successfully generated external keypair.")
        # WARNING: Sending private key over network is insecure, for DEMO ONLY.
        return jsonify({
            "public_key_hex": pub_key_hex,
            "secret_key_hex": sec_key_hex, # !!! VERY INSECURE - FOR DEMO ONLY !!!
            "message": "Store the secret_key_hex securely and use it for signing."
        })
    else:
        log.error("Failed to generate external keypair via API.")
        return jsonify({"error": "Failed to generate keypair"}), 500


@app.route('/', methods=['GET'])
def health_check():
    """Basic health check endpoint."""
    return jsonify({"status": "OK", "node_id": node_id}), 200


# --- Main Execution ---
if __name__ == '__main__':
    # Use a production-grade WSGI server like Gunicorn in the Docker CMD/ENTRYPOINT
    # For simple local running:
    # app.run(host='0.0.0.0', port=5000, debug=os.environ.get("FLASK_DEBUG", False))
    # Gunicorn is typically used in Dockerfile CMD
     log.info(f"Starting Flask application for node {node_id}...")
    # app.run(host='0.0.0.0', port=5000)
     app.run(host='0.0.0.0', port=5000, debug=os.environ.get("FLASK_DEBUG", False))   