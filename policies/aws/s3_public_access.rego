# METADATA
# title: S3 buckets must block all public access
# description: >
#   Every aws_s3_bucket_public_access_block must set all four public-access
#   guards to true. Buckets created without one are flagged.
# custom:
#   control: { cis: "2.1.5", soc2: "CC6.1", nist: "AC-3" }
#   severity: high
package guardrails.aws.s3_public_access

import rego.v1

# Collect the names of buckets that have a public-access-block with all guards on.
secured contains name if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket_public_access_block"
	after := change.change.after
	after.block_public_acls == true
	after.block_public_policy == true
	after.ignore_public_acls == true
	after.restrict_public_buckets == true
	name := after.bucket
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket"
	bucket := change.change.after.bucket
	not bucket in secured
	msg := sprintf("S3 bucket %q has no public-access block with all four guards enabled (CIS 2.1.5 / SOC2 CC6.1)", [bucket])
}
