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

## 6. Related Security Research

| Research | Relevance |
|----------|-----------|
| **Stedi STS Bug** | `${...}` variable substitution in trust policies caused incorrect policy evaluation. AWS patched this. |
| **whoAMI Attack** (Datadog, Feb 2025) | Resource name confusion attack causing RCE. Demonstrates naming edge cases are actively exploited. |
| **Rhino Security Labs** | 21+ IAM privilege escalation methods, focused on permission misconfigs. |
| **Bishop Fox iam-vulnerable** | 250+ vulnerable IAM resources, 31 escalation paths. |
| **CloudTrail Evasion via Policy Size** (Permiso) | Policies 102-131KB cause CloudTrail to log only "requestParameters too large", hiding malicious content. |
| **OIDC Trust Policy Wildcards** | Misconfigured OIDC conditions with wildcards enable cross-tenant role assumption. |
| **CVE-2025-11621** (HashiCorp Vault) | Cross-account role impersonation via cache key collision. |

---

## 7. Key Takeaways

1. **`$` cannot appear in IAM role names**, but **CAN appear in IAM role paths** per the API validation regex.
2. This means an IAM role ARN can contain `$` in the path segment: `arn:aws:iam::ACCT:role/$path/RoleName`
3. Creating role paths that mimic IAM policy variables (e.g., `/${aws:username}/`) creates a **confusion attack surface** where policy authors may inadvertently create dynamic policies instead of static ones.
4. Both `ArnEquals` and `ArnLike` treat `*` and `?` as wildcards, and these characters are valid in role paths.
5. This intersection of role paths containing `${...}` patterns and IAM policy variable substitution appears to be an **under-explored area** in cloud security research -- no published CVE, conference talk, or dedicated blog post was found covering this specific attack vector.
6. Mitigations: always escape special characters in policy documents, restrict path creation via SCPs, validate ARNs with awareness of the full allowed character set, and be explicit about policy versions.
