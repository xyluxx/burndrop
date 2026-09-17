# AWS Secrets Manager (`aws`)

Records live in AWS Secrets Manager, one secret per burndrop name, driven through the aws CLI.

## Requirements

- AWS CLI v2 on PATH (`aws --version` prints `aws-cli/2.`). v1 is not supported.
- Credentials the CLI can find: a profile (`aws configure`, `aws sso login`), environment variables, or an instance, task or pod role. `Region` and `Profile` are passed as `--region` and `--profile` when set; otherwise the CLI defaults apply.
- IAM on `arn:aws:secretsmanager:<region>:<account>:secret:burndrop/*`: `secretsmanager:CreateSecret`, `PutSecretValue`, `GetSecretValue`, `DescribeSecret`, `DeleteSecret`; `secretsmanager:ListSecrets` on `*` for listing; `kms:Decrypt` and `kms:GenerateDataKey` on the key when a customer managed key is used. The probe (`sts:GetCallerIdentity`) needs no permission.

## What is stored where

- Secret name: `burndrop/<name>` (`Prefix` changes the first part). burndrop names use only characters Secrets Manager allows, so they are kept as they are.
- SecretString: the burndrop JSON record `{"v":1,"meta":{...},"value":"<base64>"}`. Name, retention, purpose, source, fingerprint and size travel with the value. The description is `burndrop record`; no tags are set.
- On read the record's `meta.name` must equal the requested name; anything else is reported as not found.

## Commands

Every call adds `--output json --no-cli-pager` and sets `AWS_CLI_FILE_ENCODING=UTF-8`.

| Operation | Command |
|---|---|
| Probe | `aws sts get-caller-identity` |
| Put | `aws secretsmanager create-secret --name burndrop/<name> --description "burndrop record" --secret-string file://<tmp>`; on `ResourceExistsException` `aws secretsmanager put-secret-value --secret-id burndrop/<name> --secret-string file://<tmp>` |
| Get | `aws secretsmanager get-secret-value --secret-id burndrop/<name>` |
| Delete | `aws secretsmanager describe-secret --secret-id burndrop/<name>` then `aws secretsmanager delete-secret --secret-id burndrop/<name> --force-delete-without-recovery` |
| List | `aws secretsmanager list-secrets --filters Key=name,Values=burndrop/` then one `get-secret-value` per secret |

The record is written to a file with mode 0600 in the temporary directory, handed to the CLI as `file://<tmp>`, and removed as soon as the command returns. The value is never an argument or an environment variable.

## Limits

- SecretString holds 65,536 bytes. The record carries the base64 value plus metadata, so values up to 48,384 bytes are accepted; larger values, or a record that does not fit, return `ErrTooLarge`.
- Names up to 512 characters. AWS advises against names that end in a dash followed by six characters, because they look like the suffix Secrets Manager appends to ARNs.
- Every Put creates a version; Secrets Manager keeps 100 per secret and drops unlabeled ones. Do not rewrite one name more often than every 10 minutes for long.

## Costs

At the time of writing: USD 0.40 per secret per month (prorated) and USD 0.05 per 10,000 API calls. List costs one GetSecretValue per secret. Check the pricing page for your region.

## Threat notes

- Anyone with `GetSecretValue` on the secret can read it, including through resource policies and cross account grants. CloudTrail records every call with the caller identity and secret name, never the value.
- The value never appears on a command line, so process listings and shell history stay clean. `--debug` is never used, so the CLI does not log request bodies.
- `--force-delete-without-recovery` skips the recovery window: the name is reusable at once and there is no undelete. Deletion finishes asynchronously, so a Put right after a Delete of the same name can fail for a moment. A secret deleted elsewhere with a recovery window reads as not found, and Put reports that it is scheduled for deletion.
- The credential files and SSO cache under `~/.aws` unlock everything; protect them as you would the secrets.
