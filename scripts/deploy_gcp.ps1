# deploy_gcp.ps1
# ------------------------------------------
# This PowerShell script deploys the QR Blockchain Auth system
# on GCP using Terraform (if needed) and Kubernetes manifests.
# It creates a GKE cluster, retrieves its credentials,
# and applies the Kubernetes YAML configurations.
# ------------------------------------------

# --- CONFIGURATION ---
$PROJECT_ID   = "astute-charter-213919"  # ✅ CHANGE THIS to your GCP project ID
$REGION       = "us-central1"          # Modify if needed
$ZONE         = "us-central1-c"        # Modify if needed
$CLUSTER_NAME = "qr-auth-cluster"        # Name your cluster

# --- GCP Login & Configuration ---
Write-Host "Logging into GCP..."
gcloud auth login
gcloud config set project $PROJECT_ID
gcloud config set compute/zone $ZONE

# --- Create GKE Cluster ---
Write-Host "`nCreating GKE cluster '$CLUSTER_NAME'..."
# If the cluster already exists, this command might fail.
# You could wrap this in a try-catch if you want the script to continue.
gcloud container clusters create $CLUSTER_NAME --num-nodes=2 --zone $ZONE

# --- Get Cluster Credentials ---
Write-Host "`nRetrieving cluster credentials..."
gcloud container clusters get-credentials $CLUSTER_NAME --zone $ZONE

# --- (Optional) Terraform Deployment ---
# If you have a Terraform-based infrastructure setup, uncomment the following block:
# Write-Host "`nInitializing and applying Terraform configuration..."
# Push-Location "./terraform"
# terraform init
# terraform apply -auto-approve
# Pop-Location

# --- Deploy Kubernetes Manifests ---
Write-Host "`nApplying Kubernetes configurations from the 'kubernetes' folder..."
# Ensure the path points to your Kubernetes manifests. Adjust as needed.
kubectl apply -f ../kubernetes

Write-Host "`n✅ Deployment complete. Use 'kubectl get svc' to review service statuses."
