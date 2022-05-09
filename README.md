# vault-init

This is a port/adaptation of [Kelsey Hightower](https://github.com/kelseyhightower) [vault-init](https://github.com/kelseyhightower/vault-init) to AWS.

The `vault-init` service automates the process of [initializing](https://www.vaultproject.io/docs/commands/operator/init.html) HashiCorp Vault instances running on [Amazon Web Services](http://aws.amazon.com/).

After `vault-init` initializes a Vault server it stores master keys and root tokens to a user defined [SSM Path](https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html) with a custom KMS key.


This port has been modified accordingly to rely on Vault auto unseal mechanism using KMS, easing the operation of Vault and only taking care of the initialize process.
## Usage

The `vault-init` service is designed to be run alongside a Vault server and communicate over local host.

## Configuration

The vault-init service supports the following environment variables for configuration:

* `VAULT_INIT_CHECK_INTERVAL` - The time in seconds between Vault health checks. (300)
* `VAULT_INIT_ROOT_TOKEN_SSM_PATH` - The SSM path where to store the root token generated on init
* `VAULT_INIT_UNSEAL_KEYS_SSM_PATH` - The SSM path where to store the keys generated on init
* `VAULT_KMS_KEY_ID` - The Amazon KMS key ID used to encrypt and decrypt the vault master key and root token.
* `VAULT_INIT_VAULT_ADDR` - The vault API address.

### Example Values

```
VAULT_INIT_CHECK_INTERVAL="300"
VAULT_INIT_ROOT_TOKEN_SSM_PATH="VAULT/DC1_TEST/ROOT_TOKEN"
VAULT_INIT_UNSEAL_KEYS_SSM_PATH="VAULT/DC1_TEST/UNSEAL_KEYS"
VAULT_KMS_KEY_ID="arn:aws:kms:us-east-1:1234567819:key/dead-beef-dead-beef-deadbeefdead"
VAULT_INIT_VAULT_ADDR="https://vault.service.consul:8200"
```

### AWS

The `vault-init` service needs the following set of resources:

- IAM Role + Instance Profile
- KMS Key

Here's a minimal example which creates an instance profile that can use a KMS key and read/write to a private S3 bucket.

```hcl
resource "aws_iam_role" "vault" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Effect": "Allow"
    }
  ]
}
EOF
}

# use the current caller's ARN as the KMS key administrator
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "vault" {
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Id": "vault-key-policy",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "${data.aws_caller_identity.current.arn}"},
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Principal": {"AWS": "${aws_iam_role.vault.arn}"},
      "Action": [
	"kms:Encrypt",
	"kms:Decrypt",
	"kms:ReEncrypt*",
	"kms:GenerateDataKey*",
	"kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_kms_alias" "vault" {
  name          = "alias/my-vault-key"
  target_key_id = "${aws_kms_key.vault.key_id}"
}

resource "aws_iam_role_policy" "vault" {
  role	 = "${aws_iam_role.vault.id}"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
	"kms:ReEncrypt*",
	"kms:GenerateDataKey*",
	"kms:Encrypt",
	"kms:DescribeKey",
	"kms:Decrypt"
      ],
      "Effect": "Allow",
      "Resource": "${aws_kms_alias.vault.arn}"
    },
    {
      "Action": [
        "ssm:PutParameter",
        "ssm:GetParameter",
      ],
      "Effect": "Allow",
      "Resource": "ssm://VAULT/*"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "vault" {
  role = "${aws_iam_role.vault.name}"
}
```
