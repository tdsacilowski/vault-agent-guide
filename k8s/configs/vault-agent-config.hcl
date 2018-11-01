exit_after_auth = true
pid_file = "./pidfile"

auto_auth {
    method "kubernetes" {
        mount_path = "auth/kubernetes"
        config = {
        role = "example"
        }
    }

    sink "file" {
        config = {
        path = "/home/vault/.vault-token"
        }
    }
}
