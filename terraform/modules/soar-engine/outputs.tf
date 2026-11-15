output "audit_logs_bucket_name" {
  description = "The name of the S3 audit bucket storing CloudTrail management events"
  value       = aws_s3_bucket.audit_logs.id
}

output "audit_logs_bucket_arn" {
  description = "The ARN of the S3 audit bucket"
  value       = aws_s3_bucket.audit_logs.arn
}

output "cloudtrail_arn" {
  description = "The ARN of the central multi-region CloudTrail"
  value       = aws_cloudtrail.main_audit_trail.arn
}

output "security_incidents_sns_topic_arn" {
  description = "The ARN of the security operations SNS topic"
  value       = aws_sns_topic.security_incidents.arn
}

output "s3_lockdown_lambda_arn" {
  description = "The ARN of the S3 lockdown SOAR Lambda function"
  value       = aws_lambda_function.s3_lockdown.arn
}

output "s3_lockdown_lambda_name" {
  description = "The name of the S3 lockdown SOAR Lambda function"
  value       = aws_lambda_function.s3_lockdown.function_name
}

output "s3_lockdown_role_arn" {
  description = "The ARN of the IAM execution role for S3 lockdown Lambda"
  value       = aws_iam_role.s3_lockdown_role.arn
}

output "iam_quarantine_lambda_arn" {
  description = "The ARN of the IAM quarantine SOAR Lambda function"
  value       = aws_lambda_function.iam_quarantine.arn
}

output "iam_quarantine_lambda_name" {
  description = "The name of the IAM quarantine SOAR Lambda function"
  value       = aws_lambda_function.iam_quarantine.function_name
}

output "s3_lockdown_dlq_arn" {
  description = "The ARN of the S3 lockdown SQS Dead Letter Queue"
  value       = aws_sqs_queue.s3_lockdown_dlq.arn
}

output "s3_lockdown_dlq_name" {
  description = "The name of the S3 lockdown SQS Dead Letter Queue"
  value       = aws_sqs_queue.s3_lockdown_dlq.name
}

output "iam_quarantine_dlq_arn" {
  description = "The ARN of the IAM quarantine SQS Dead Letter Queue"
  value       = aws_sqs_queue.iam_quarantine_dlq.arn
}

output "iam_quarantine_dlq_name" {
  description = "The name of the IAM quarantine SQS Dead Letter Queue"
  value       = aws_sqs_queue.iam_quarantine_dlq.name
}

output "s3_eventbridge_rule_arn" {
  description = "The ARN of the S3 tampering / exfiltration EventBridge rule"
  value       = aws_cloudwatch_event_rule.s3_security_rule.arn
}

output "iam_eventbridge_rule_arn" {
  description = "The ARN of the IAM privilege escalation / compromise EventBridge rule"
  value       = aws_cloudwatch_event_rule.iam_security_rule.arn
}
