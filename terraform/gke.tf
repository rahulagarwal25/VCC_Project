# Using Autopilot by default (controlled by var.gke_autopilot)
resource "google_container_cluster" "autopilot_cluster" {
  count = var.gke_autopilot ? 1 : 0

  name     = var.gke_cluster_name
  location = var.gcp_region
  project  = var.project_id

  enable_autopilot = true

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.private.id

  ip_allocation_policy {
    cluster_secondary_range_name  = google_compute_subnetwork.private.secondary_ip_range[0].range_name # Pods
    services_secondary_range_name = google_compute_subnetwork.private.secondary_ip_range[1].range_name # Services
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false # Keep public endpoint accessible for kubectl unless using bastion/VPN
    master_ipv4_cidr_block  = "172.16.0.32/28" # Example internal CIDR for control plane
  }
  master_authorized_networks_config {} # Allows access from anywhere if public endpoint enabled

  # Default node pool is managed by Autopilot
  remove_default_node_pool = true
  initial_node_count       = 1 # Required placeholder even for Autopilot
}

# --- GKE Standard Cluster (Optional, if var.gke_autopilot is false) ---
resource "google_container_cluster" "standard_cluster" {
  count = !var.gke_autopilot ? 1 : 0

  name     = var.gke_cluster_name
  location = var.gcp_region
  project  = var.project_id

  remove_default_node_pool = true
  initial_node_count       = 1 # Will be replaced by our node pool

  network    = google_compute_network.main.id
  subnetwork = google_compute_subnetwork.private.id

  ip_allocation_policy {
    cluster_secondary_range_name  = google_compute_subnetwork.private.secondary_ip_range[0].range_name # Pods
    services_secondary_range_name = google_compute_subnetwork.private.secondary_ip_range[1].range_name # Services
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false # Keep public endpoint accessible
    master_ipv4_cidr_block  = "172.16.0.32/28" # Example
  }
  master_authorized_networks_config {}

  # Disable basic auth and client certificate
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }
}

resource "google_container_node_pool" "standard_primary_nodes" {
  count = !var.gke_autopilot ? 1 : 0

  name       = "${google_container_cluster.standard_cluster[0].name}-node-pool"
  location   = var.gcp_region
  cluster    = google_container_cluster.standard_cluster[0].name
  node_count = var.gke_standard_node_count
  project    = var.project_id

  node_config {
    machine_type = var.gke_standard_machine_type
    # Define service account, disk size, etc. if needed
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform", # Broad scope for simplicity
    ]
    # Ensure nodes have access to Artifact Registry, etc.
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }
}