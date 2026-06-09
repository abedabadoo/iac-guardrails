# iac-guardrails

**Policy-as-code security gate for Terraform.** A growing library of [OPA](https://www.openpolicyagent.org/)/Rego
policies that scan Terraform plans in CI and block insecure infrastructure before it ships — every policy
mapped to **CIS AWS Foundations Benchmark**, **SOC 2**, and **NIST 800-53** controls, with a CLI that turns
results into an auditor-readable compliance report.

> Compliance as infrastructure: a guardrail isn't a checklist someone fills out after the fact — it's a test
> that fails the build.

[![Guardrails](https://github.com/abedabadoo/iac-guardrails/actions/workflows/guardrails.yml/badge.svg)](https://github.com/abedabadoo/iac-guardrails/actions/workflows/guardrails.yml)

## Why

Most cloud incidents trace back to a misconfiguration that a human was supposed to catch in review — a public
S3 bucket, an SSH port open to the world, an unencrypted volume. `iac-guardrails` moves that catch *left*, into
CI, as code:

- **Engineers** get a fast, specific failure on the PR instead of a finding in next quarter's audit.
- **GRC** gets evidence: every control is a versioned, tested policy with a pass/fail fixture, mapped to the
  framework language an auditor actually speaks.

## How it works

```
terraform plan -out=plan.out
terraform show -json plan.out > plan.json
conftest test plan.json -p policies/        # gate the build
python cli/report.py plan.json              # human/auditor report mapped to controls
```

Each policy is a `deny` rule over the Terraform plan's `resource_changes`. Policies live in `policies/aws/`,
each with a Rego unit test (`*_test.rego`) carrying a passing and a failing fixture, runnable offline with
`opa test`. Control mappings live in `controls/mapping.yaml`.

## Quickstart

```bash
make test        # opa unit tests for every policy
make scan        # conftest against fixtures/
make report      # compliance report from a sample plan
```

Requires [`opa`](https://www.openpolicyagent.org/docs/latest/#running-opa),
[`conftest`](https://www.conftest.dev/install/), and Python 3.11+.

## Policy coverage

See [`controls/mapping.yaml`](controls/mapping.yaml) for the live control matrix and
[`ROADMAP.md`](ROADMAP.md) for what's shipping next. Coverage grows one control at a time —
each as its own reviewed PR with a test.

## License

MIT — see [LICENSE](LICENSE).
