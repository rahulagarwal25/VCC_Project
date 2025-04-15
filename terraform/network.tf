resource "google_compute_network" "main" {
  name                    = var.vpc_network_name
  auto_create_subnetworks = false # We will create a custom subnet
  project                 = var.project_id
}

resource "google_compute_subnetwork" "private" {
  name          = var.vpc_subnetwork_name
  ip_cidr_range = "10.0.1.0/24" # Example CIDR
  region        = var.gcp_region
  network       = google_compute_network.main.id
  project       = var.project_id

  # Required for Internal Load Balancer used by GKE Service
  private_ip_google_access = true

  # Required for GKE Autopilot or Private Standard Clusters
  secondary_ip_range {
    range_name    = "gke-pods-range"
    ip_cidr_range = "10.4.0.0/14" # Example Pod range
  }
  secondary_ip_range {
    range_name    = "gke-services-range"
    ip_cidr_range = "10.5.0.0/20" # Example Service range
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "${var.vpc_network_name}-allow-internal"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
  # Allow all traffic within the VPC (adjust for stricter rules in production)
  source_ranges = [google_compute_subnetwork.private.ip_cidr_range]
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "${var.vpc_network_name}-allow-ssh"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  # Allow SSH from anywhere - restrict in production!
  source_ranges = ["0.0.0.0/0"]
  # Optionally add target_tags = ["ssh-enabled"] and apply tag to GCE instance
}

resource "google_compute_firewall" "allow_gke_control_plane" {
  name    = "${var.vpc_network_name}-allow-gke-cp"
  network = google_compute_network.main.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["443", "10250"] # HTTPS and kubelet
  }

  # Allow GKE control plane to reach nodes. Find the control plane CIDR from the created cluster if needed.
  # For Autopilot or Public Endpoint Standard: This might be GCP IPs or a specific range.
  # For Private Endpoint Standard: This is the master_ipv4_cidr_block defined in gke.tf
  # Using a broad range for simplicity here, refine if needed.
  # source_ranges = ["<GKE Control Plane IP Range>"] # Replace with actual range if needed, depends on GKE config
  source_ranges = ["0.0.0.0/0"] # Overly permissive, ok for demo if firewalling externally
}