# AWS Security Lambda Toolkit

Community PoC examples for AWS security monitoring and lightweight SOC workflows. Reconstructed examples, not exact exports of deployed functions. Python 3.12; boto3 provided by Lambda. Each handler is `<filename_without_py>.lambda_handler`. Package soc_findings_ingestion.py alongside soc_cloudtrail_poller.py. No credentials or account-specific identifiers included.

| Module | Trigger | Environment | Minimum execution permissions (in addition to CloudWatch logging) |
|---|---|---|---|
| iam_security_alert_processor | EventBridge IAM CloudTrail API events | SNS_TOPIC_ARN | sns:Publish |
| soc_findings_ingestion | EventBridge GuardDuty/Security Hub | TABLE_NAME | dynamodb:PutItem |
| soc_cloudtrail_poller | Scheduled EventBridge | TABLE_NAME, REGIONS (optional), LOOKBACK_MINUTES (optional) | cloudtrail:LookupEvents, dynamodb:PutItem |
| soc_critical_notifier | DynamoDB stream NEW_IMAGE | SNS_TOPIC_ARN | DynamoDB stream read permissions, sns:Publish |
| security_group_monitor | Scheduled EventBridge | SNS_TOPIC_ARN (optional) | ec2:DescribeSecurityGroups, optional sns:Publish |
| orphan_resource_scanner | Scheduled EventBridge | SNS_TOPIC_ARN (optional) | ec2:DescribeVolumes, ec2:DescribeAddresses, optional sns:Publish |

DynamoDB: string partition key finding_id; optional GSI with GSI1PK and GSI1SK string keys. First observation wins; subsequent updates to the same finding are intentionally ignored in this simple PoC. CloudTrail polling is regional, rate limited and only covers management event history; use an overlapping schedule and monitor failures. EventBridge IAM global service events generally arrive in us-east-1. Configure triggers, Lambda resource permissions, execution roles, confirmed SNS subscriptions and resource-scoped IAM separately.Stream retries can duplicate notifications. Scanner examples are report-only and do not delete or remediate resources. Review SNS payload sizes, log/data privacy, throttling, retries, DLQs and finding lifecycle before production. No live AWS testing performed. Validate against your deployed versions before publishing as tested work.
