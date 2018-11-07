vault {
  renew_token = false
  retry {
    backoff = "1s"
  }
}

# KV v2: https://github.com/hashicorp/nomad/blob/c6d9dba7b54898cb9c6925b407e6e18e464f8d34/website/source/docs/job-specification/template.html.md#vault-kv-api-v2
template {
  destination = "/etc/secrets/index.html"
  contents = <<EOH
  <html>
  <body>
  <p>Some secrets:</p>
  {{- with secret "secret/data/myapp/config" }}
  <ul>
  <li><pre>username: {{ .Data.data.username }}</pre></li>
  <li><pre>password: {{ .Data.data.password }}</pre></li>
  </ul>
  {{ end }}
  </body>
  </html>  
  EOH
}
