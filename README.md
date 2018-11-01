# Vault Agent Guide

The purpose of this guide is to provide working examples on how to use the Vault Agent. Vault Agent is a client daemon that can perform useful tasks. Currently, it provides a mechanism for easy authentication to Vault in a wide variety of environments. The documentation for using Vault Agent can be found [here](https://www.vaultproject.io/docs/agent/).

## The Challenge

How to enable authentication to Vault and manage the lifecycle of tokens in a standard way (without having to write custom logic)?

## Background

Nearly all requests to Vault must be accompanied by an authentication token. This includes all API requests, as well as via the Vault CLI and other libraries.

Vault provides a number of different authentication methods to assist in delivery of this initial token (AKA secret zero). If you can securely get the first secret from an originator to a consumer, all subsequent secrets transmitted between this originator and consumer can be authenticated with the trust established by the successful distribution and user of that first secret. Getting the first secret to the consumer, is the **secure introduction** challenge.

To that end, Vault provides integration with native authentication capabilities in various environments, for example: IAM in [AWS](https://www.vaultproject.io/docs/auth/aws.html) and [Google Cloud](https://www.vaultproject.io/docs/auth/gcp.html), Managed Service Identities in [Azure](https://www.vaultproject.io/docs/auth/azure.html), and Service Accounts in [Kubernetes](https://www.vaultproject.io/docs/auth/kubernetes.html). Complete documentation for all Vault-supported authentication methods can be found [here](https://www.vaultproject.io/docs/auth/index.html).

However, even though Vault provides a number of mechanisms to support secure introduction, it's always been the responsibility of the client to write their own logic for enabling this behavior and managing the lifecycle of tokens.

## Vault Agent Auto-Auth

To that end, HashiCorp has introduced the Vault Agent which provides a nunber of different helper features, specifically addressing the following challenges
 
- Automatic authentication
- Secure delivery/storage of tokens
- Lifecycle management of these tokens (renewal & reauthentication)

> ***NOTE:*** The Vault Agent Auto-Auth functionality addresses the challenges related to obtaining and managing ***authentication tokens only***.
> 
> Helper tools for obtaining and managing secrets stored in Vault (e.g. DB credentials, PKI certificates, AWS access keys, etc.) include [Consul Template](https://github.com/hashicorp/consul-template) and [Envconsul](https://github.com/hashicorp/envconsul). See the linked documentation for the respective tools for more information.

For documentation on both basic and advanced functionality, please refer to the Vault Agent Auto-Auth [documentation](https://www.vaultproject.io/docs/agent/autoauth/index.html).

To summarize, Vault Agent Auto-Auth relies on a configuration file that defines a "Method" which specifies parameters around what auth method to use and associated parameters as well as one or more "Sinks" which are locations where Vault Agent will write the acquired token to. Additionally, Sink configuration allows for [response-wrapping](https://www.vaultproject.io/docs/concepts/response-wrapping.html) (see [here](https://learn.hashicorp.com/vault/secrets-management/sm-cubbyhole) also) the tokens.

> ***NOTE:*** An experimental feature, which will not be covered in this guide, also allows for encrypting the tokens. Stay tuned for more detail on this...

This guide will focus on demonstrating the documented functionality using the following examples:

- EC2 authentication via the AWS IAM auth method
- Pod authentication via the Kubernetes auth method
- [Stretch] Combining AWS IAM auth with Nomad + Vault

## EC2 Auto-Auth Using the AWS IAM Auth Method

To complete this section of the guide, you will need the following:

- An AWS account and associated credentials that allow for the creation of resources
- A EC2 instance with and instance profile attached (the associated IAM policy for the instance profile is not relevant to the context of Vault)
- A running Vault cluster that is accessible from the EC2 instance identified above

For an example of quick-start Terraform code for deploying a single-node Vault cluster and a bare EC2 instance on which to test, please see [this repo](https://github.com/tdsacilowski/vault-demo/tree/master/terraform-aws).

> ***NOTE:*** The example Terraform code in the above repository is not suitable for production use. For examples on best-practices on deploying a Vault cluster, see [here](https://github.com/hashicorp/vault-guides/tree/master/operations/provision-vault) and [here](https://registry.terraform.io/modules/hashicorp/vault/aws/0.10.3).

### Part 1: Configure the AWS IAM Auth Method

In this section, we'll write some dummy data/policies and configure Vault to allow AWS IAM authentication from specifies IAM roles.

1. [From the Vault **Server**] If you haven't done so already, perform a `vault operator init`. Make sure to note down your unseal keys and initial root token in a safe place. You will need these in the following steps (in production, you would secure these in a much better way, or use auto-unseal).

2. [From the Vault **Server**] If your Vault server is sealed, perform the `vault operator unseal` operation using 3 different unseal keys.

3. [From the Vault **Server**] Login using your initial root token (or other administrative login that you might have already configured).

4. [From the Vault **Server**] Lets create some dummy data and a read-only policy for our clients:

    ```
    vault policy write myapp-kv-ro - <<EOH
    path "secret/myapp/*" {
        capabilities = ["read", "list"]
    }
    EOH

    vault kv put secret/myapp/config \
        ttl="30s" \
        username="appuser" \
        password="suP3rsec(et!"
    ```

5. Enable the aws auth method:

    ```
    $ vault auth enable aws

    Success! Enabled aws auth method at: aws/
    ```

6. [From the Vault **Server**] Next, configure the AWS credentials that Vault will use to verify login requests from AWS clients:
   
    ```
    $ vault write -force auth/aws/config/client

    Success! Data written to: auth/aws/config/client
    ```

    > ***NOTE:*** In the above example, I'm relying on an instance profile to provide credentials to Vault. See [here](https://www.vaultproject.io/docs/auth/aws.html#recommended-vault-iam-policy) for an example IAM policy to give Vault in order for it to handle AWS IAM auth. You can also pass in explicit credentials as such:

    ```
    $ vault write auth/aws/config/client secret_key=AWS_SECRET_ACCESS_KEY access_key=AWS_ACCESS_KEY_ID
    ```

7. Identify the IAM instance profile role associated with the client instance that you intend to authenticate from.
   
    If you're using the sample repo linked above in the intro, you'll have a `"${var.environment_name}-vault-client"` instance created for you with an instance profile role of `"${var.environment_name}-vault-client-role"`.

    If you're provisioning your own examples, spin up an EC2 instance and assign it any instance profile, the IAM role policy is not important from Vault's perspective. What *is* important is the fact that a `vault login` operation from the client instance can use the attached instance profile as a way to identify itself to Vault.

    [From the Vault **Server**] Configure a **Vault** role under the AWS authentication method that we configured in the previous step. A Vault auth role maps an AWS IAM role to a set of Vault policies (I'll reference the dummy policy created in step #4):
   
    ```
    $ vault write auth/aws/role/dev-role-iam auth_type=iam \
        bound_iam_principal_arn=arn:aws:iam::AWS_ACCOUNT_NUMBER:role/teddy-vault-demo-vault-client-role \
        policies=myapp-kv-ro \
        ttl=24h

    Success! Data written to: auth/aws/role/dev-role-iam
    ```

    > ***NOTE:*** To get your IAM role ARN, you'll need to go to the AWS console and find the role associated with the instance profile that you want to use as a source of authentication. If you're following along with the quick-start repo, the instance will have the AWS CLI installed and you can simply run the following to obtain information about the IAM role:

    ```
    $ aws iam get-role --role-name [VAR_ENVIRONMENT_NAME]-vault-client-role
    {
        "Role": {
            "Path": "/",
            "RoleName": "[VAR_ENVIRONMENT_NAME]-vault-client-role",
            "RoleId": "ROLE_ID_VALUE",
            "Arn": "arn:aws:iam::AWS_ACCOUNT_NUMBER:role/[VAR_ENVIRONMENT_NAME]-vault-client-role",
            "CreateDate": "2018-11-01T01:54:07Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        }
    }
    ```

### Part 2: Login Manually From the Client Instance

Now that we've configured the appropriate AWS IAM auth method on our Vault server, let's SSH into our **client** instance and verify that we're able to successfully utilize the instance profile to login to Vault.

1. [From the Vault **Client**] Open a terminal on your client instance. If using the quick-start repo, the Vault binary should already be installed and configured to talk to your Vault server. You can check this by typing in `vault status`:

    ```
    $ vault status

    Key             Value
    ---             -----
    Seal Type       shamir
    Initialized     true
    Sealed          false
    Total Shares    5
    Threshold       3
    Version         0.11.4
    Cluster Name    vault-cluster-0c4710e6
    Cluster ID      34226d12-3707-6d75-8407-772b32ee4c40
    HA Enabled      true
    HA Cluster      https://active.vault-us-east-1.service.consul-us-east-1.consul:8201
    HA Mode         active
    ```

    If following with your own examples, make sure you've downloaded the appropriate [Vault binary](https://releases.hashicorp.com/vault/) and set your VAULT_ADDR environment variable, for example:

    ```
    export VAULT_ADDR=http://10.0.101.79:8200
    ```

2. [From the Vault **Client**] Using the Vault CLI, test the `login` operation:

    ```
    $ vault login -method=aws role=dev-role-iam

    Success! You are now authenticated. The token information displayed below
    is already stored in the token helper. You do NOT need to run "vault login"
    again. Future Vault requests will automatically use this token.

    Key                                Value
    ---                                -----
    token                              tBJ6tSUMGRm...
    token_accessor                     jgVEZtmy5DdkLnZ29yJfSP6g
    token_duration                     24h
    token_renewable                    true
    token_policies                     ["default" "myapp-kv-ro"]
    identity_policies                  []
    policies                           ["default" "myapp-kv-ro"]
    token_meta_client_user_id          CLIENT_USER_ID_VALUE
    token_meta_inferred_aws_region     n/a
    token_meta_inferred_entity_id      n/a
    token_meta_inferred_entity_type    n/a
    token_meta_account_id              AWS_ACCOUNT_NUMBER
    token_meta_auth_type               iam
    token_meta_canonical_arn           arn:aws:iam::AWS_ACCOUNT_NUMBER:role/teddy-vault-demo-vault-client-role
    token_meta_client_arn              arn:aws:sts::AWS_ACCOUNT_NUMBER:assumed-role/teddy-vault-demo-vault-client-role/i-03d2b2...
   ```

3. [From the Vault **Client**] We can also check to make sure that the token has the appropriate permissions to read our secrets:

    ```
    $ vault kv get secret/myapp/config

    ====== Data ======
    Key         Value
    ---         -----
    password    suP3rsec(et!
    ttl         30s
    username    appuser
    ```

### Part 3: Using Vault Agent Auto-Auth on the Client Instance

In this section we'll take everything we've done so far and apply it to the Vault Agent Auto-Auth method and write out a token to an arbitrary location on disk.

1. [From the Vault **Client**] First, we'll create a configuration file for the Vault Agent to use:

    ```
    tee /home/ubuntu/auto-auth-conf.hcl <<EOF
    exit_after_auth = true
    pid_file = "./pidfile"

    auto_auth {
        method "aws" {
            mount_path = "auth/aws"
            config = {
                type = "iam"
                role = "dev-role-iam"
            }
        }

        sink "file" {
            config = {
                path = "/home/ubuntu/vault-token-via-agent"
            }
        }
    }
    EOF
    ```

    In this file, we're telling Vault Agent to use the `aws` auth method, located at the path `auth/aws` on our Vault server, authenticating against the IAM role `dev-role-iam`.

    We're also identifying a location on disk where we want to place this token. The `sink` block can be configured multiple times if we want Vault Agent to place the token into multiple locations.

2. [From the Vault **Client**] Now we'll run the Vault Agent with the above config:

    ```
    $ vault agent -config=/home/ubuntu/auto-auth-conf.hcl -log-level=debug

    ==> Vault agent configuration:

                        Cgo: disabled
                Log Level: debug
                    Version: Vault v0.11.4
                Version Sha: 612120e76de651ef669c9af5e77b27a749b0dba3

    ==> Vault server started! Log data will stream in below:

    2018-11-01T04:04:50.407Z [INFO]  sink.file: creating file sink
    2018-11-01T04:04:50.408Z [INFO]  sink.file: file sink configured: path=/home/ubuntu/vault-token-via-agent
    2018-11-01T04:04:50.410Z [INFO]  sink.server: starting sink server
    2018-11-01T04:04:50.410Z [INFO]  auth.handler: starting auth handler
    2018-11-01T04:04:50.410Z [INFO]  auth.handler: authenticating
    2018-11-01T04:04:50.443Z [INFO]  auth.handler: authentication successful, sending token to sinks
    2018-11-01T04:04:50.443Z [INFO]  auth.handler: starting renewal process
    2018-11-01T04:04:50.443Z [INFO]  sink.file: token written: path=/home/ubuntu/vault-token-via-agent
    2018-11-01T04:04:50.443Z [INFO]  sink.server: sink server stopped
    2018-11-01T04:04:50.443Z [INFO]  sinks finished, exiting
    ```

3. [From the Vault **Client**] Let's try an API call using the token that Vault Agent pulled for us to test:

    ```
    $ curl \
        --header "X-Vault-Token: $(cat /home/ubuntu/vault-token-via-agent)" \
        $VAULT_ADDR/v1/secret/myapp/config | jq
    
    {
        "request_id": "af09f402-05ad-31e2-ac3d-05aae441fd51",
        "lease_id": "",
        "renewable": false,
        "lease_duration": 30,
        "data": {
            "password": "suP3rsec(et!",
            "ttl": "30s",
            "username": "appuser"
        },
        "wrap_info": null,
        "warnings": null,
        "auth": null
    }
    ```