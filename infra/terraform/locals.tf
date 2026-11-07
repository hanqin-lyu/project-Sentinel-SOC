locals {
  tags = merge(
    {
      project    = "sentinel-soc"
      managed_by = "terraform"
    },
    var.extra_tags
  )
}
