variable "build_resource_group_name" {
  default = "dvls-lab-services-production"
  type    = string
}

variable "client_id" {
  default = env("AZURE_CLIENT_ID")
  type    = string
}

variable "client_secret" {
  default = env("AZURE_CLIENT_SECRET")
  type    = string
}

variable "image_name" {
  default = "dvls-lab-service-base"
  type    = string
}

variable "image_resource_group_name" {
  default = "dvls-lab-services-production"
  type    = string
}

variable "lab_git_ref" {
  default = "master"
  type    = string
}

variable "subscription_id" {
  default = env("AZURE_SUBSCRIPTION_ID")
  type    = string
}

variable "tenant_id" {
  default = env("AZURE_TENANT_ID")
  type    = string
}

variable "username" {
  default = "devolutions"
  type    = string
}

variable "windows_iso_url" {
  default = env("WINDOWS_ISO_URL")
  type    = string
}
