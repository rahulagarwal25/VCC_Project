#!/bin/bash

# Script to deploy infrastructure using Terraform and apply Kubernetes manifests

# --- Configuration ---
# !!! Replace with your Project ID !!!
PROJECT_ID="astute-charter-213919"
# !!! Replace with your GCP region !!!
REGION="us-central1"
# !!! Replace with your Artifact Registry repo name if different !!!
AR_REPO_NAME="qr-auth-repo"
# --- End Configuration ---

# Get the directory of the script
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BASE_DIR=$(dirname "$SCRIPT_DIR") # Parent directory (qr-blockchain-auth/)

# 1. Deploy Infrastructure with Terraform
echo "------------------------------------"
echo "Deploying GCP Infrastructure with Terraform..."
echo "------------------------------------"
cd "${BASE_DIR}/terraform" || exit 1

# Initialize Terraform (only needed once or after provider changes)
terraform init

# Apply Terraform configuration
# Pass Project ID and Region as variables
terraform apply -var="project_id=${PROJECT_ID}" -var="gcp_region=${REGION}" -auto-approve
if [ $? -ne 0 ]; then
  echo "ERROR: Terraform apply failed."
  exit 1
fi

# Get GKE cluster credentials (assuming Terraform output is available or predictable name)
CLUSTER_NAME=$(terraform output -raw gke_cluster_name)
CLUSTER_LOCATION=$(terraform output -raw gke_cluster_location)

echo "------------------------------------"
echo "Configuring kubectl for cluster: ${CLUSTER_NAME} in ${CLUSTER_LOCATION}"
echo "------------------------------------"
gcloud container clusters get-credentials "${CLUSTER_NAME}" --region "${CLUSTER_LOCATION}" --project "${PROJECT_ID}"
if [ $? -ne 0 ]; then
  echo "ERROR: Failed to get GKE credentials."
  exit 1
fi

# 2. Prepare Kubernetes Manifests
echo "------------------------------------"
echo "Preparing Kubernetes Manifests..."
echo "------------------------------------"
cd "${BASE_DIR}/kubernetes" || exit 1

# Construct the full image path
AR_URL="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPO_NAME}"
BC_IMAGE="${AR_URL}/blockchain-node:latest"
AS_IMAGE="${AR_URL}/auth-service:latest"

# Use 'sed' to replace placeholder image paths in K8s YAML files
# Make backups just in case
echo "Updating image paths in Kubernetes manifests..."
sed -i.bak "s|gcr.io/YOUR_PROJECT_ID/blockchain-node:latest|${BC_IMAGE}|g" blockchain-node-statefulset.yaml
sed -i.bak "s|us-central1-docker.pkg.dev/YOUR_PROJECT_ID/qr-auth-repo/blockchain-node:latest|${BC_IMAGE}|g" blockchain-node-statefulset.yaml # Use new AR format if present

sed -i.bak "s|gcr.io/YOUR_PROJECT_ID/auth-service:latest|${AS_IMAGE}|g" auth-service-deployment.yaml
sed -i.bak "s|us-central1-docker.pkg.dev/YOUR_PROJECT_ID/qr-auth-repo/auth-service:latest|${AS_IMAGE}|g" auth-service-deployment.yaml # Use new AR format if present

# !!! Replace placeholder JWT Secret in Deployment - VERY INSECURE FOR DEMO ONLY !!!
# In production use K8s secrets injected as env vars or mounted files.
# Generate a random secret for demo or use a fixed one (less secure)
DEMO_JWT_SECRET=$(openssl rand -hex 16) # Generate a random secret for this deployment
echo "Using temporary JWT Secret: ${DEMO_JWT_SECRET} (DEMO ONLY)"
sed -i.bak "s|DEMO_JWT_SECRET_REPLACE_ME|${DEMO_JWT_SECRET}|g" auth-service-deployment.yaml

# 3. Deploy Applications to GKE
echo "------------------------------------"
echo "Applying Kubernetes Manifests..."
echo "------------------------------------"
# Apply namespace first
kubectl apply -f namespace.yaml

# Apply all other manifests in the directory
kubectl apply -f .
if [ $? -ne 0 ]; then
  echo "ERROR: kubectl apply failed."
  # Optionally try to clean up or provide rollback instructions
  exit 1
fi

echo "------------------------------------"
echo "Deployment script finished."
echo "Wait for pods to become ready: kubectl get pods -n qr-auth -w"
echo "Find Internal Load Balancer IP: kubectl get svc auth-service-internal-lb -n qr-auth -o jsonpath='{.status.loadBalancer.ingress[0].ip}'"
echo "------------------------------------"

# Clean up backup files created by sed
find . -name '*.bak' -delete
cd "$BASE_DIR" || exit 1