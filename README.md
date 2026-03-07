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

### 6.2 `aws-samples/kubernetes-for-java-developers` — Unquoted `$EKS_KUBECTL_ROLE_ARN`

**Repo:** [aws-samples/kubernetes-for-java-developers/buildspec.yml](https://github.com/aws-samples/kubernetes-for-java-developers/blob/master/buildspec.yml)

```yaml
# buildspec.yml — post_build phase
CREDENTIALS=$(aws sts assume-role --role-arn $EKS_KUBECTL_ROLE_ARN \
  --role-session-name codebuild-kubectl --duration-seconds 900)
```

The variable `$EKS_KUBECTL_ROLE_ARN` is **unquoted**. In a CodeBuild environment, if this environment variable contains shell metacharacters (from a role path like `/${injection}/`), word splitting and command substitution will occur.

### 6.3 CVE-2025-5277: `alexei-led/aws-mcp-server` — Command Injection (CVSS 9.6)

**Repo:** [alexei-led/aws-mcp-server](https://github.com/alexei-led/aws-mcp-server)
**Advisory:** [GHSA-m4qw-j7mx-qv6h](https://github.com/advisories/GHSA-m4qw-j7mx-qv6h)
**Fix Commit:** [94d20ae](https://github.com/alexei-led/aws-mcp-server/commit/94d20ae1798a43ac7e3a28e71900d774e5159c8a)

The `cli_executor.py` module executed AWS CLI commands without proper input sanitization. Shell metacharacters (`;`, `|`, `&&`, `||`, `` ` ``, `$()`) in MCP request parameters — including role ARNs — were interpreted by the shell.

The fix introduced `validate_aws_command()` and `validate_pipe_command()` functions to sanitize input before execution.

**Timeline:** Disclosed April 8, 2025. Partially fixed April 10. CVE published May 28, 2025.

### 6.4 `aws/aws-parallelcluster-node` — Subprocess Injection Validators Added

**Repo:** [aws/aws-parallelcluster-node CHANGELOG](https://github.com/aws/aws-parallelcluster-node/blob/develop/CHANGELOG.md)

Version 3.5.0 changelog entry:
> "Add validators to prevent malicious string injection while calling the subprocess module."

This Python package runs on EC2 instances and uses `subprocess` to execute Slurm scheduler commands (`scontrol`, etc.). The security fix added input validation to prevent injection through user-controllable strings passed to these commands — which could include role ARNs or paths in certain configurations.

### 6.5 Widespread `eval $(assume-role ...)` Community Pattern

The extremely common pattern for assuming roles in shell scripts:
```bash
eval $(aws sts assume-role --role-arn "$ROLE_ARN" ... | jq -r '...')
```

This is referenced in:
- [remind101/assume-role](https://github.com/remind101/assume-role) — `eval $(assume-role prod)`
- [AWS CLI Issue #7546](https://github.com/aws/aws-cli/issues/7546) — Feature request for `aws sts assume-role` to output shell-compatible variable definitions
- Multiple community gists and blog posts

When the role ARN is sourced from an untrusted input (API response, config file, environment variable), and the `eval` pattern is used, a malicious role path containing `$(malicious-command)` will execute the injected command.

### 6.6 `aws/aws-cli` — `export-credentials --format env` with Unquoted `eval`

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

### 6.7 `aws/rolesanywhere-credential-helper` — Unquoted `${ROLE_ARN}` in README

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

### 6.8 `aws-ia/terraform-aws-control_tower_account_factory` — ARN Construction from Shell Variables

**Repo:** [aws-ia/terraform-aws-control_tower_account_factory](https://github.com/aws-ia/terraform-aws-control_tower_account_factory)
**Issue:** [#219](https://github.com/aws-ia/terraform-aws-control_tower_account_factory/issues/219)

The `creds.sh` script constructs ARNs from shell variables:
```bash
CREDENTIALS=$(aws sts assume-role \
  --role-arn "arn:${AWS_PARTITION}:iam::${AFT_MGMT_ACCOUNT}:role/${AFT_MGMT_ROLE}" \
  --role-session-name "${ROLE_SESSION_NAME}")
```

While the outer variable is quoted, the ARN is built from multiple environment variables (`${AWS_PARTITION}`, `${AFT_MGMT_ACCOUNT}`, `${AFT_MGMT_ROLE}`) that could individually contain injection payloads. When `${AWS_PARTITION}` was unset, it produced malformed ARNs. In a multi-tenant environment, if any of these component variables are attacker-influenced, injection is possible within the quoted string via the component values themselves.

### 6.9 `aws-actions/configure-aws-credentials` — Character Sanitization (Safe)

**Repo:** [aws-actions/configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials)

The GitHub Action sanitizes special characters in `GITHUB_ACTOR` and `GITHUB_WORKFLOW` when used in session tags (replacing invalid characters with `*`). The `role-to-assume` input parameter is passed directly to the AWS SDK, not through a shell — making it resistant to this class of injection. The Action also handles special characters in `AWS_SECRET_ACCESS_KEY` via a retry mechanism ([Issue #599](https://github.com/aws-actions/configure-aws-credentials/issues/599)).

### 6.10 Safe Patterns (for contrast)

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

## 7. Related Security Research

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

## 8. Key Takeaways

1. **`$` cannot appear in IAM role names**, but **CAN appear in IAM role paths** per the API validation regex.
2. This means an IAM role ARN can contain `$` in the path segment: `arn:aws:iam::ACCT:role/$path/RoleName`
3. Creating role paths that mimic IAM policy variables (e.g., `/${aws:username}/`) creates a **confusion attack surface** where policy authors may inadvertently create dynamic policies instead of static ones.
4. Both `ArnEquals` and `ArnLike` treat `*` and `?` as wildcards, and these characters are valid in role paths.
5. This intersection of role paths containing `${...}` patterns and IAM policy variable substitution appears to be an **under-explored area** in cloud security research -- no published CVE, conference talk, or dedicated blog post was found covering this specific attack vector.
6. Mitigations: always escape special characters in policy documents, restrict path creation via SCPs, validate ARNs with awareness of the full allowed character set, and be explicit about policy versions.
