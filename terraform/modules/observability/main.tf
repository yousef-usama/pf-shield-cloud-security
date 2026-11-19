# ---------------------------------------------------------------------------------------------------------------------
# 1. SECURITY OPERATIONS CLOUDWATCH DASHBOARD
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "security_ops" {
  count          = var.enable_dashboard ? 1 : 0
  dashboard_name = "pf-shield-security-ops-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", var.s3_lockdown_lambda_name, { stat = "Sum", label = "S3 Lockdown Invocations" }],
            [".", "Errors", ".", ".", { stat = "Sum", label = "S3 Lockdown Errors", color = "#d62728" }],
            [".", "Invocations", "FunctionName", var.iam_quarantine_lambda_name, { stat = "Sum", label = "IAM Quarantine Invocations" }],
            [".", "Errors", ".", ".", { stat = "Sum", label = "IAM Quarantine Errors", color = "#ff7f0e" }],
            ["PF-Shield/SecurityOps", "MeanTimeToRemediate", "Playbook", "S3Lockdown", { stat = "Average", label = "S3 Lockdown MTTR (sec)" }],
            [".", "MeanTimeToRemediate", "Playbook", "IAMQuarantine", { stat = "Average", label = "IAM Quarantine MTTR (sec)" }]
          ]
          period = 300
          region = "me-central-1"
          title  = "SOAR Playbook Executions & Containment MTTR"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiId", var.api_id, { stat = "Sum", label = "Total Requests" }],
            [".", "4xx", ".", ".", { stat = "Sum", label = "4xx Client Errors", color = "#ffbb78" }],
            [".", "5xx", ".", ".", { stat = "Sum", label = "5xx Server Errors", color = "#d62728" }],
            [".", "Latency", ".", ".", { stat = "p95", label = "p95 Latency (ms)", color = "#2ca02c" }]
          ]
          period = 300
          region = "me-central-1"
          title  = "Edge HTTP API Health & Anti-Scraping Metrics"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.s3_lockdown_dlq_name, { stat = "Maximum", label = "S3 Lockdown DLQ Depth" }],
            [".", "ApproximateNumberOfMessagesVisible", "QueueName", var.iam_quarantine_dlq_name, { stat = "Maximum", label = "IAM Quarantine DLQ Depth" }]
          ]
          period = 60
          region = "me-central-1"
          title  = "Dead Letter Queue Depth (Zero-Dropped Alert SLA)"
          view   = "timeSeries"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/S3", "NumberOfObjects", "BucketName", var.kyc_vault_bucket_name, "StorageType", "AllStorageTypes", { stat = "Average", label = "Total Vault Objects" }],
            [".", "BucketSizeBytes", ".", ".", ".", "StandardStorage", { stat = "Average", label = "Standard Storage Bytes" }]
          ]
          period = 86400
          region = "me-central-1"
          title  = "Zero-Trust KYC Vault Storage & Retention"
          view   = "singleValue"
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------------------------------------------------
# 2. PROACTIVE SECURITY METRIC ALARMS
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "soar_s3_dlq_not_empty" {
  alarm_name          = "pf-soar-s3-dlq-not-empty-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Critical: SOAR S3 Lockdown DLQ has received dropped security messages"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = var.s3_lockdown_dlq_name
  }
}

resource "aws_cloudwatch_metric_alarm" "soar_iam_dlq_not_empty" {
  alarm_name          = "pf-soar-iam-dlq-not-empty-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Critical: SOAR IAM Quarantine DLQ has received dropped security messages"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = var.iam_quarantine_dlq_name
  }
}

resource "aws_cloudwatch_metric_alarm" "api_5xx_spike" {
  alarm_name          = "pf-api-5xx-spike-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "5xx"
  namespace           = "AWS/ApiGateway"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "High: API Gateway experiencing elevated 5xx error rate"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    ApiId = var.api_id
  }
}

resource "aws_cloudwatch_metric_alarm" "soar_lambda_errors" {
  alarm_name          = "pf-soar-s3-lambda-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Critical: S3 Lockdown SOAR playbook encountered an execution failure"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = var.s3_lockdown_lambda_name
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests_high" {
  count               = var.enable_waf && var.waf_web_acl_name != null ? 1 : 0
  alarm_name          = "pf-waf-blocked-requests-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "High: WAFv2 WebACL blocked more than 50 malicious requests in 5 minutes"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = "me-central-1"
    Rule   = "ALL"
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_ratelimit_triggered" {
  count               = var.enable_waf && var.waf_web_acl_name != null ? 1 : 0
  alarm_name          = "pf-waf-ratelimit-scrapers-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 20
  alarm_description   = "Medium: WAF anti-scraping rate limit triggered by aggressive IP"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = var.waf_web_acl_name
    Region = "me-central-1"
    Rule   = "RateLimitScrapers"
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_5xx_errors" {
  count               = var.alb_arn_suffix != null ? 1 : 0
  alarm_name          = "pf-alb-target-5xx-high-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Critical: Application Load Balancer targets returning elevated 5xx error rates"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_4xx_probing" {
  count               = var.alb_arn_suffix != null ? 1 : 0
  alarm_name          = "pf-alb-target-4xx-probing-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_4XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "High: Elevated 4xx error rate on ALB targets indicating automated directory fuzzing"
  alarm_actions       = [var.sns_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }
}

