package guardrails.aws.s3_public_access

import rego.v1

# A bucket with a complete public-access block -> no denial.
test_secured_bucket_allowed if {
	count(deny) == 0 with input as {"resource_changes": [
		{
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "secure-bucket"}},
		},
		{
			"type": "aws_s3_bucket_public_access_block",
			"change": {"after": {
				"bucket": "secure-bucket",
				"block_public_acls": true,
				"block_public_policy": true,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}
}

# A bucket with no public-access block -> denied.
test_bucket_without_block_denied if {
	count(deny) == 1 with input as {"resource_changes": [
		{
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "naked-bucket"}},
		},
	]}
}

# A bucket whose block leaves one guard off -> denied.
test_bucket_partial_block_denied if {
	count(deny) == 1 with input as {"resource_changes": [
		{
			"type": "aws_s3_bucket",
			"change": {"after": {"bucket": "leaky-bucket"}},
		},
		{
			"type": "aws_s3_bucket_public_access_block",
			"change": {"after": {
				"bucket": "leaky-bucket",
				"block_public_acls": true,
				"block_public_policy": false,
				"ignore_public_acls": true,
				"restrict_public_buckets": true,
			}},
		},
	]}
}
