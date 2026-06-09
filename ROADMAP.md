# Roadmap

Ordered backlog. Each item ships as its own PR: a Rego policy + a passing fixture + a failing fixture +
a unit test + a row in `controls/mapping.yaml`. Check an item off (`- [x]`) when its PR merges.

The daily guardrails agent implements the **first unchecked item** each run, opens a PR, and stops.
One item per PR. No batching. No auto-merge.

## Shipped

- [x] **S3 — block public access** · CIS 2.1.5 · SOC 2 CC6.1 · NIST AC-3
- [x] **Security Group — no 0.0.0.0/0 to port 22 (SSH)** · CIS 5.2 · SOC 2 CC6.6 · NIST SC-7

## Backlog — AWS

- [ ] **Security Group — no 0.0.0.0/0 to port 3389 (RDP)** · CIS 5.2 · CC6.6 · SC-7
- [ ] **S3 — bucket encryption at rest enabled (SSE)** · CIS 2.1.1 · CC6.1 · SC-28
- [ ] **S3 — bucket versioning enabled** · CIS 2.1.3 · A1.2 · CP-9
- [ ] **S3 — access logging enabled** · CIS 3.6 · CC7.2 · AU-2
- [ ] **EBS — volumes encrypted** · CIS 2.2.1 · CC6.1 · SC-28
- [ ] **RDS — storage encrypted** · CIS 2.3.1 · CC6.1 · SC-28
- [ ] **RDS — not publicly accessible** · CIS 2.3.3 · CC6.6 · SC-7
- [ ] **RDS — automated backups retention >= 7 days** · A1.2 · CP-9
- [ ] **CloudTrail — enabled in all regions** · CIS 3.1 · CC7.2 · AU-2
- [ ] **CloudTrail — log file validation enabled** · CIS 3.2 · CC7.2 · AU-9
- [ ] **CloudTrail — logs encrypted with KMS** · CIS 3.7 · CC6.1 · SC-28
- [ ] **IAM — password policy minimum length >= 14** · CIS 1.8 · CC6.1 · IA-5
- [ ] **IAM — no policies with full `*:*` admin** · CIS 1.16 · CC6.3 · AC-6
- [ ] **IAM — no inline user policies (use groups/roles)** · CC6.3 · AC-6
- [ ] **IAM — MFA required in assume-role trust policies** · CIS 1.10 · CC6.6 · IA-2
- [ ] **KMS — key rotation enabled** · CIS 3.8 · CC6.1 · SC-12
- [ ] **EC2 — IMDSv2 required (no IMDSv1)** · CC6.6 · SC-7
- [ ] **EC2 — no public IP auto-assign on instances** · CC6.6 · SC-7
- [ ] **VPC — default security group restricts all traffic** · CIS 5.3 · CC6.6 · SC-7
- [ ] **VPC — flow logs enabled** · CIS 3.9 · CC7.2 · AU-2
- [ ] **ELB/ALB — listeners enforce TLS (no plaintext HTTP)** · CC6.7 · SC-8
- [ ] **ELB/ALB — access logging enabled** · CC7.2 · AU-2
- [ ] **Lambda — no plaintext secrets in environment variables** · CC6.1 · IA-5
- [ ] **ECR — image scan-on-push enabled** · CC7.1 · RA-5
- [ ] **ECR — tag immutability enabled** · CC8.1 · CM-3
- [ ] **SQS/SNS — server-side encryption enabled** · CC6.1 · SC-28
- [ ] **DynamoDB — encryption at rest with CMK** · CC6.1 · SC-28
- [ ] **EKS — control-plane logging enabled** · CC7.2 · AU-2
- [ ] **Secrets Manager — rotation enabled** · CC6.1 · IA-5
- [ ] **Tagging — all resources carry `owner` + `data-classification`** · CC1.4 · CM-8

## Backlog — engine / DX

- [ ] **CLI — `--format sarif` output for GitHub Security tab**
- [ ] **CLI — severity levels (block on high/critical, warn on medium)**
- [ ] **CLI — exemptions file (`.guardrails-ignore.yaml`) with required justification + expiry**
- [ ] **Report — group findings by control framework (CIS / SOC 2 / NIST views)**
- [ ] **CI — comment the compliance report on the PR**
- [ ] **AI layer — LLM explains each failure in plain English + suggests the minimal fix**
- [ ] **Docs site — auto-generated control matrix from `mapping.yaml`**
