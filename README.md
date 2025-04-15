# Quantum-Resistant Cross-Cloud Auth via Blockchain


This project implements a **quantum-secure, federated authentication system** leveraging post-quantum cryptography (PQC), blockchain identity management, and cross-cloud JWT-based verification.


The system is composed of two microservices:
- **Auth Service** (`auth_service/`): Handles authentication, token issuance, and verification.
- **Blockchain Node** (`blockchain_node/`): Anchors identities on a local blockchain with quantum-signed blocks.

It is deployed via Kubernetes (`kubernetes/`), orchestrated with Terraform (`terraform/`), and automatable through PowerShell/Bash scripts (`scripts/`).

### 🔐 Key Features
- Post-quantum cryptography using **liboqs** (Dilithium3)
- DID-style identity registration with block inclusion
- JWT-based token issuance and validation
- Fully containerized deployment over **GCP GKE**, adaptable to AWS/Azure
- Persistent blockchain nodes with StatefulSets and volume claims


### 🚀 Quick Start
```bash
# 1. Build Docker Images
cd scripts
./build_images.ps1  # or build_images.sh for Linux

# 2. Deploy to GKE using Terraform and Kubernetes
terraform init && terraform apply
./deploy_gcp.ps1  # or deploy_gcp.sh
```


### 📡 API Endpoints
**Auth Service**
- `POST /authenticate` – Authenticate using signed message
- `POST /verify_token` – Verify JWT
- `POST /register_identity_proxy` – Proxy identity to blockchain node
- `GET /` – Health check

**Blockchain Node**
- `POST /register` – Register new identity
- `GET /get_public_key?identity=...` – Get public key for identity
- `GET /chain` – Full blockchain view
- `GET /generate_keys` – Generate quantum-safe keypair


### 🧭 Architecture & Layer Diagrams
- `BlockChain Node Architecture.jpeg`
- `Auth Service Architecture.jpeg`
- `Crypto Layer Diagram.jpeg`
- `Kubernetes Architecture.jpeg`
- `API Gateway Layer Diagram.jpeg`
- `TerraForm Architecture Diagram.jpeg`


### 🔒 Security & Quantum Resistance
- Uses **Dilithium3** for signatures, pluggable via `.env`
- Can swap to SPHINCS+/XMSS via `crypto_qr.py`
- TLS upgrade paths tested via `liboqs` + OpenSSL fork
- Tokens validated with audience & issuer matching


### ☁️ Infrastructure-as-Code (Terraform)
- `terraform/network.tf`: VPC and subnet configuration
- `terraform/gke.tf`: GKE cluster provisioning
- `terraform/outputs.tf`: Exports cluster details for deployment scripts


### 📜 Credits & Attribution
- Based on NIST post-quantum finalists: **Dilithium3, Kyber**
- Blockchain structure inspired by academic prototypes
- Special thanks to `liboqs`, `Gunicorn`, `Kubernetes`, and GCP
