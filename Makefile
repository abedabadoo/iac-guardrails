.PHONY: test scan report fail-check all

# Unit-test every Rego policy (offline, no cloud needed).
test:
	opa test policies/ -v

# Run the guardrails against the secure fixture — should pass clean.
scan:
	conftest test fixtures/pass/secure_plan.json -p policies/ --all-namespaces

# Confirm the insecure fixture is correctly blocked (negative test).
fail-check:
	@if conftest test fixtures/fail/insecure_plan.json -p policies/ --all-namespaces; then \
		echo "ERROR: insecure fixture passed — a guardrail isn't firing"; exit 1; \
	else echo "OK: insecure fixture blocked"; fi

# Auditor-readable compliance report from the insecure fixture.
report:
	@conftest test fixtures/fail/insecure_plan.json -p policies/ --all-namespaces --output json > /tmp/guardrails.json || true
	@python3 cli/report.py --conftest-json /tmp/guardrails.json

all: test scan fail-check report
