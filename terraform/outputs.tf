output "gke_cluster_name" {
  value = var.gke_autopilot ? google_container_cluster.autopilot_cluster[0].name : google_container_cluster.standard_cluster[0].name
}

output "gke_cluster_endpoint" {
  description = "GKE cluster public endpoint"
  value       = var.gke_autopilot ? google_container_cluster.autopilot_cluster[0].endpoint : google_container_cluster.standard_cluster[0].endpoint
  sensitive   = true # Endpoint might be sensitive depending on config
}

output "gke_cluster_location" {
  value = var.gke_autopilot ? google_container_cluster.autopilot_cluster[0].location : google_container_cluster.standard_cluster[0].location
}

output "vpc_network_name" {
  value = google_compute_network.main.name
}

output "vpc_subnetwork_name" {
  value = google_compute_subnetwork.private.name
}

output "gce_instance_name" {
  value = google_compute_instance.simulation_client.*.name # Use splat operator for conditional resource
}

output "gce_instance_zone" {
  value = google_compute_instance.simulation_client.*.zone
}

output "gce_instance_internal_ip" {
  value = google_compute_instance.simulation_client.*.network_interface.0.network_ip
}