package phase16

deny contains message if {
  some change in input.resource_changes
  change.type == "google_storage_bucket"
  change.change.after.public_access_prevention != "enforced"
  message := sprintf("bucket %s does not enforce public access prevention", [change.address])
}

deny contains message if {
  some change in input.resource_changes
  change.type == "google_cloud_run_v2_service"
  change.change.after.ingress == "INGRESS_TRAFFIC_ALL"
  message := sprintf("service %s permits public ingress", [change.address])
}

deny contains message if {
  some change in input.resource_changes
  image := change.change.after.template[0].containers[0].image
  change.type == "google_cloud_run_v2_service"
  not regex.match("@sha256:[0-9a-f]{64}$", image)
  message := sprintf("service %s image is not digest pinned", [change.address])
}
