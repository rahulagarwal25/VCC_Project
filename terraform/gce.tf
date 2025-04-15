resource "google_compute_instance" "simulation_client" {
  # Only create if needed explicitly (e.g., add a variable var.create_gce_instance)
  # count = var.create_gce_instance ? 1 : 0
  count = 1 # Create one for demo purposes

  name         = var.gce_instance_name
  machine_type = var.gce_machine_type
  zone         = "${var.gcp_region}-a" # Choose a zone in the region
  project      = var.project_id

  tags = ["ssh-enabled"] # Optional tag for firewall rule targeting

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11" # Or another preferred image
      size  = 10 # GB
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.private.id
    # No external IP needed if accessing via SSH through IAP or Bastion
    # Add access_config {} for external IP if required, but less secure
    # access_config {}
  }

  # Allow SSH access via OS Login or metadata keys
  metadata = {
    enable-oslogin = "TRUE"
    # Or add ssh-keys = "user:ssh-rsa AAAA..."
  }

  # Install necessary tools for testing (Python, pip, git, etc.)
  metadata_startup_script = <<-EOT
    #!/bin/bash
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip git curl
    pip3 install requests # Install requests for test_client.py
    # Potentially install liboqs dependencies and oqs-python here too if needed
    # apt-get install -y build-essential cmake libssl-dev ninja-build
    # pip3 install oqs
    echo "Startup script finished."
  EOT

  service_account {
    # Use default compute service account or create a dedicated one
    scopes = ["cloud-platform"] # Broad scope for simplicity
  }

  depends_on = [
    google_compute_subnetwork.private
  ]
}