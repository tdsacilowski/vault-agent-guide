vault {
  renew_token = false
  retry {
    backoff = "1s"
  }
}
template {
  contents = <<EOH
  {{- with secret "secret/myapp/config" }}
  username: {{ .Data.username }}
  password: {{ .Data.password }}
  {{ end }}
  EOH
destination = "/etc/secrets/config"
}
template {
  contents = <<EOH
  {{- with secret "secret/myapp/config" }}
  username: {{ .Data.username }}
  password: {{ .Data.password }}
  {{ end }}
  EOH
destination = "/etc/secrets/index.html"
}

