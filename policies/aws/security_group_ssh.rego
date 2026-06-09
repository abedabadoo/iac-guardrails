# METADATA
# title: Security groups must not expose SSH (22) to the world
# description: >
#   Denies any security group ingress rule that allows TCP/22 from
#   0.0.0.0/0 or ::/0.
# custom:
#   control: { cis: "5.2", soc2: "CC6.6", nist: "SC-7" }
#   severity: high
package guardrails.aws.security_group_ssh

import rego.v1

world_cidrs := {"0.0.0.0/0", "::/0"}

# A rule covers port 22 if 22 falls within [from_port, to_port].
covers_ssh(rule) if {
	rule.from_port <= 22
	rule.to_port >= 22
}

open_to_world(rule) if {
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in world_cidrs
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_security_group"
	some rule in change.change.after.ingress
	covers_ssh(rule)
	open_to_world(rule)
	name := object.get(change.change.after, "name", change.address)
	msg := sprintf("Security group %q exposes SSH (22) to the world (CIS 5.2 / SOC2 CC6.6)", [name])
}

# Also catch standalone aws_security_group_rule resources.
deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_security_group_rule"
	after := change.change.after
	after.type == "ingress"
	after.from_port <= 22
	after.to_port >= 22
	some cidr in object.get(after, "cidr_blocks", [])
	cidr in world_cidrs
	msg := sprintf("Security group rule %q exposes SSH (22) to the world (CIS 5.2 / SOC2 CC6.6)", [change.address])
}
