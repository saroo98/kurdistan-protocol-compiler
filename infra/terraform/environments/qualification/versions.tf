terraform {
  required_version = "= 1.15.8"
  backend "gcs" {}
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.43.0"
    }
  }
}

provider "google" { region = var.region }
