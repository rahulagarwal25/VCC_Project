terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.gcp_region
}

variable "project_id" {
  description = "Your GCP Project ID"
  type        = string
  # default     = "your-gcp-project-id" # Or set via TF_VAR_project_id env var
}

variable "gcp_region" {
  description = "GCP Region for resources"
  type        = string
  default     = "us-central1"
}

variable "gke_cluster_name" {
  description = "Name for the GKE cluster"
  type        = string
  default     = "qr-auth-cluster"
}

variable "vpc_network_name" {
  description = "Name for the VPC Network"
  type        = string
  default     = "qr-auth-vpc"
}

variable "vpc_subnetwork_name" {
  description = "Name for the VPC Subnetwork"
  type        = string
  default     = "qr-auth-subnet"
}

variable "gce_instance_name" {
  description = "Name for the optional GCE simulation instance"
  type        = string
  default     = "simulation-client-vm"
}

variable "gce_machine_type" {
  description = "Machine type for the GCE instance"
  type        = string
  default     = "e2-micro" # Free tier eligible
}

variable "gke_autopilot" {
  description = "Use GKE Autopilot (true) or Standard (false)"
  type        = bool
  default     = true # Simpler for demo purposes
}

variable "gke_standard_machine_type" {
  description = "Machine type for GKE Standard nodes (if autopilot is false)"
  type        = string
  default     = "e2-small"
}

variable "gke_standard_node_count" {
  description = "Number of nodes for GKE Standard cluster (if autopilot is false)"
  type        = number
  default     = 1
}