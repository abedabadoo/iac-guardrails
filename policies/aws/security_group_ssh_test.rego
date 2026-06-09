package guardrails.aws.security_group_ssh

import rego.v1

test_world_open_ssh_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.web",
		"change": {"after": {
			"name": "web",
			"ingress": [{
				"from_port": 22,
				"to_port": 22,
				"cidr_blocks": ["0.0.0.0/0"],
			}],
		}},
	}]}
}

test_scoped_ssh_allowed if {
	count(deny) == 0 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.web",
		"change": {"after": {
			"name": "web",
			"ingress": [{
				"from_port": 22,
				"to_port": 22,
				"cidr_blocks": ["10.0.0.0/8"],
			}],
		}},
	}]}
}

# A wide port range (0-65535) open to the world also covers 22 -> denied.
test_wide_range_covers_ssh_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.allports",
		"change": {"after": {
			"name": "allports",
			"ingress": [{
				"from_port": 0,
				"to_port": 65535,
				"cidr_blocks": ["0.0.0.0/0"],
			}],
		}},
	}]}
}

test_ipv6_world_open_ssh_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_security_group",
		"address": "aws_security_group.web6",
		"change": {"after": {
			"name": "web6",
			"ingress": [{
				"from_port": 22,
				"to_port": 22,
				"ipv6_cidr_blocks": ["::/0"],
			}],
		}},
	}]}
}

test_standalone_rule_world_open_denied if {
	count(deny) == 1 with input as {"resource_changes": [{
		"type": "aws_security_group_rule",
		"address": "aws_security_group_rule.ssh",
		"change": {"after": {
			"type": "ingress",
			"from_port": 22,
			"to_port": 22,
			"cidr_blocks": ["0.0.0.0/0"],
		}},
	}]}
}
