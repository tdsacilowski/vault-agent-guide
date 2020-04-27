# Vault Agent: Kubernetes Auth Method Examples

- [Vault Agent: Kubernetes Auth Method Examples](#vault-agent-kubernetes-auth-method-examples)
  - [Prerequisites](#prerequisites)
  - [Configure the Vault Kubernetes Auth Method](#configure-the-vault-kubernetes-auth-method)
  - [Example 1: Deploy Pod With Vault Agent Sidecar](#example-1-deploy-pod-with-vault-agent-sidecar)
  - [References](#references)

In this document, we will walk through configuring Vault's [Kubernetes Auth Method](https://www.vaultproject.io/docs/auth/kubernetes) in order to demonstrate how we can delegate Kubernetes authentication and authorization checks to Vault. We will also run through some examples on how we can use this auth method to perform secrets retrieval from within our running Pods.

## Prerequisites

The following should be available and accessible before continuing on with the examples:

- A Kubernetes or OpenShift environment to test in, where we have permissions to create service accounts
  - In this example, we'll use a local development installation of OpenShift 3.x using [Minishift](https://docs.okd.io/3.11/minishift/getting-started/index.html)
  - If a standard Kubernetes environment is preferred, follow along with [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/); any relevant differences will ne noted where applicable
- A running Vault instance reachable from your Kubernetes or OpenShift environment
- The `kubectl` command-line tool, configured to communicate with your cluster
- The [Vault CLI](https://www.vaultproject.io/downloads) to easily interact with your Vault server
  - Configure it to point to your Vault server by setting the `VAULT_ADDR` environment variable
  - Log into Vault with a user that has permissions to add and configure auth mounts, policies, and secrets engines

> In order to simplify this document, the term "Kubernetes" will be used to refer to either a standard Kubernetes or OpenShift deployment; the examples here can be run on either.
>
> While OpenShift provides the `oc` binary as its `kubectl` equivalent, we will still use `kubectl` commands for the examples below, for the sake of simplicity.
>
> If running this example within a Minishift environment, make sure to login as the `admin` user (default user is `developer`). To do this, we need the `oc` binary to be configured. This can be done by running the `minishift oc-env` command and setting our `PATH` envorinment variable as directed. Once set, we can login using the `oc login -u system:admin` command.

## Configure the Vault Kubernetes Auth Method

In this section, we'll walk through the steps to configure the Vault Kubernetes auth method.

In our Kubernetes environment, create the `vault-auth` service account and grant it the appropriate ClusterRoleBinding ([`system:auth-delegator`](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#other-component-roles)) which will be used to delegate authentication and authorization checks to Vault.

> **NOTE**: Be mindful of the namespaces used throughout these examples. The following objects will all need to be created in the same namespace (when using Minishift, this will be `myproject`):
>
> - The `vault-auth` service account
> - The `auth-delegator` ClusterRoleBinding
> - The example Pod's service account
> - The Vault Kubernetes auth method role for our example Pod
> - The example Pod itself

```bash
# Determine the IP address that Pods should use to reach an external Vault instance
# Vault address to use from within a Pod
# Minishift:
export EXAMPLE_VAULT_ADDR=http://$(minishift ssh "route -n | grep ^0.0.0.0 | awk '{ print \$2 }'"):8200

# Uncomment the below for Minikube
# export EXAMPLE_VAULT_ADDR=http://$(minikube ssh "route -n | grep ^0.0.0.0 | awk '{ print \$2 }'"):8200

# Set variables for our examples
export EXAMPLE_K8S_NAMESPACE="myproject"
export EXAMPLE_VAULT_AUTH_SA="vault-auth"
export EXAMPLE_TEST_SA="test-app"

# Create a service account for Vault and cluster role binding
# for the auth-delegator role
kubectl create -n ${EXAMPLE_K8S_NAMESPACE} serviceaccount ${EXAMPLE_VAULT_AUTH_SA}

kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: role-tokenreview-binding
  namespace: ${EXAMPLE_K8S_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: ${EXAMPLE_VAULT_AUTH_SA}
  namespace: ${EXAMPLE_K8S_NAMESPACE}
EOF
```

In order to configure Vault to connect to our Kubernetes cluster, we need to determine the appropriate values to set our Kubernetes [auth method configuration parameters](https://www.vaultproject.io/api/auth/kubernetes#parameters) to:

- `kubernetes_host` (`string: <required>`) - Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server.
- `kubernetes_ca_cert` (`string: ""`) - PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API. NOTE: Every line must end with a newline: `\n`
- `token_reviewer_jwt` (`string: ""`) - A service account JWT used to access the TokenReview API to validate other JWTs during login. If not set the JWT used for login will be used to access the API.

```bash
# When creating a service account, Kubernetes will create a secret to hold the
# Service Account's JWT; here we retrieve the full identifier for that secret
# Note: OpenShift will create two secrets for each service account, so we pull the
# one with "token" in the name
# See: https://docs.openshift.com/container-platform/3.11/dev_guide/service_accounts.html#dev-managing-service-accounts
VAULT_SA_SECRET_NAME=$(kubectl get serviceaccounts vault-auth -o go-template='{{range .secrets}}{{.name}}{{"\n"}}{{end}}' | awk '/token/ {print}')

# Retrieve the JWT for our service account
VAULT_SA_JWT_TOKEN=$(kubectl get secret ${VAULT_SA_SECRET_NAME} -o go-template='{{index .data "token"}}' | base64 --decode; echo)

# Retrieve the service account's CA cert used to verify the serving certificate of the Kubernetes API server
# See: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
VAULT_SA_CA_CRT=$(kubectl get secret ${VAULT_SA_SECRET_NAME} -o go-template='{{index .data "ca.crt"}}' | base64 --decode; echo)

# Retrieve IP address to access the Kubernetes API server
K8S_APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
```

On our Vault server, mount and configure the Kubernetes auth method using the default (`/auth/kubernetes`) path:

```bash
# Set the Vault address for our CLI to use
# NOTE: this is different than the Vault address that Pods use from within our cluster
#
# In this example, Vault is deployed locally and listening on 0.0.0.0:8200
# (Using 0.0.0.0 instead of 127.0.0.1 enables Vault to be addressable by the Kubernetes cluster and its Pods because it binds to a shared network)
export VAULT_ADDR=http://0.0.0.0:8200

# Enable the Kubernetes auth method at the default path ("auth/kubernetes")
vault auth enable kubernetes

# Configure the Kubernetes auth method with the appropriate connection details
vault write auth/kubernetes/config token_reviewer_jwt="${VAULT_SA_JWT_TOKEN}" kubernetes_host="${K8S_APISERVER}" kubernetes_ca_cert="${VAULT_SA_CA_CRT}"
```

In the last configuration step, we perform the following tasks:

- Create a Kubernetes service account to bind our example Pods to
- Create a simple ACL policy that will provide our examples read-only access to a set of secrets in our KV path
- Create a Kubernetes auth method role in Vault that maps the service account for our example Pods to defined Vault policies

```bash
# Create a service account for our example Pod
kubectl create serviceaccount test-app

# Create a policy file, myapp-kv-ro.hcl
# This assumes that the Vault server is running kv v1 (non-versioned kv)
echo '
path "secret/myapp/*" {
    capabilities = ["read", "list"]
}' | vault policy write myapp-kv-ro -

# Create a role named, 'example' to map Kubernetes Service Account to
# Vault policies and default token TTL
vault write auth/kubernetes/role/example bound_service_account_names=${EXAMPLE_TEST_SA} bound_service_account_namespaces=${EXAMPLE_K8S_NAMESPACE} policies=myapp-kv-ro ttl=24h
```

You can now test your configuration to see if everything has been set up correctly using the following example:

```bash
# Starts a temporary Pod using a simple container image with a shell, using
# the "test-app" service account created above
kubectl run tmp -i --tty --rm --serviceaccount=test-app --image alpine \
    --env="VAULT_ADDR=${EXAMPLE_VAULT_ADDR}" -- sh -c ' \
    apk add curl jq && \
    K8S_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && \
    curl --silent --request POST --data "{\"jwt\": \"$K8S_TOKEN\", \"role\": \"example\"}" $VAULT_ADDR/v1/auth/kubernetes/login | jq'
```

If successful, you should see output similar to the following:

```json
{
  "request_id": "e4bf9286-9f98-7a77-2986-2a81549989f0",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "wrap_info": null,
  "warnings": null,
  "auth": {
    "client_token": "s.8ILjPmo8sZOr8BMWPp0XwuGi",
    "accessor": "r6Mo78NbZifVdVbCuwKi5POK",
    "policies": [
      "default",
      "myapp-kv-ro"
    ],
    "token_policies": [
      "default",
      "myapp-kv-ro"
    ],
    "metadata": {
      "role": "example",
      "service_account_name": "test-app",
      "service_account_namespace": "myproject",
      "service_account_secret_name": "test-app-token-gmm6m",
      "service_account_uid": "bf5567d8-8816-11ea-8af5-0800279f4ad4"
    },
    "lease_duration": 86400,
    "renewable": true,
    "entity_id": "18e1db08-5fd8-39c2-3cd6-f12fa44db622",
    "token_type": "service",
    "orphan": true
  }
}
```

With the Vault Kubernetes auth method configured, we can now dive into individual examples.

## Example 1: Deploy Pod With Vault Agent Sidecar

In this example, we'll deploy a simple [Kubernetes Pod](https://kubernetes.io/docs/concepts/workloads/pods/pod-overview/) that does the following:

- Uses the [Vault agent](https://www.vaultproject.io/docs/agent) running as an [Init Container](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/) to authenticate to Vault
- Uses a [Vault agent template](https://www.vaultproject.io/docs/agent/template) to pull secrets from the appropriate KV path and writes them to a shared mount in our Pod
- Deploys a simple Nginx container that serves up a simple web page to display the secrets from #2

Before continuing, write some simple KV data into Vault:

```bash
# Create test data in the `secret/myapp` path.
vault kv put secret/myapp/config username='appuser' password='suP3rsec(et!' ttl='30s'
```

Before deploying the example Pod, create a `ConfigMap` resource with configuration values for the Vault agent authentication and [template](https://www.vaultproject.io/docs/agent/template) functionality:

```bash
# Create a ConfigMap for our Pod to pass in the Vault agent configuration
kubectl create -f - <<EOF
apiVersion: v1
data:
  vault-agent-config.hcl: |
    # Comment this out if running as sidecar instead of initContainer
    exit_after_auth = true

    pid_file = "/home/vault/pidfile"

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

    template {
    destination = "/etc/secrets/index.html"
    contents = <<EOT
    <html>
    <body>
    <p>Some secrets:</p>
    {{- with secret "secret/myapp/config" }}
    <ul>
    <li><pre>username: {{ .Data.username }}</pre></li>
    <li><pre>password: {{ .Data.password }}</pre></li>
    </ul>
    {{ end }}
    </body>
    </html>
    EOT
    }
kind: ConfigMap
metadata:
  name: example-vault-agent-config
  namespace: ${EXAMPLE_K8S_NAMESPACE}
EOF
```

Create our Pod from the spec defined below:

```bash
# Write the example Pod spec
tee example-pod.yaml <<EOF
---
apiVersion: v1
kind: Pod
metadata:
  name: vault-agent-example
  namespace: ${EXAMPLE_K8S_NAMESPACE}
spec:
  serviceAccountName: test-app
  
  volumes:
  - configMap:
      items:
      - key: vault-agent-config.hcl
        path: vault-agent-config.hcl
      name: example-vault-agent-config
    name: config
  - emptyDir: {}
    name: shared-data

  initContainers:
  - args:
    - agent
    - -config=/etc/vault/vault-agent-config.hcl
    - -log-level=debug
    env:
    - name: VAULT_ADDR
      value: ${EXAMPLE_VAULT_ADDR}
    image: vault
    name: vault-agent
    volumeMounts:
    - mountPath: /etc/vault
      name: config
    - mountPath: /etc/secrets
      name: shared-data

  containers:
  - image: nginx
    name: nginx-container
    ports:
    - containerPort: 80
    volumeMounts:
    - mountPath: /usr/share/nginx/html
      name: shared-data
EOF

# Run the Pod
kubectl apply -f example-pod.yaml --record

# Validate that you can see the generated HTML with secrets
# (after forwarding, go to localhost:8080)
kubectl port-forward pod/vault-agent-example 8080:80
```

## References

- https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/
- https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/
- https://kubernetes.io/docs/reference/kubectl/
- https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- https://kubernetes.io/docs/concepts/overview/working-with-objects/kubernetes-objects/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/
- https://docs.openshift.com/container-platform/3.10/cli_reference/differences_oc_kubectl.html
- https://kubernetes.io/docs/setup/learning-environment/minikube/
- https://code-ready.github.io/crc/
