import os, json, boto3

def lambda_handler(event, context):
    d = event.get('detail', {})
    if d.get('errorCode'): return {'status': 'ignored_failed_call'}
    name = d.get('eventName', 'Unknown')
    critical = {'UpdateAssumeRolePolicy','AttachRolePolicy','PutRolePolicy','CreateAccessKey','DeleteRolePermissionsBoundary','DeactivateMFADevice','SetDefaultPolicyVersion'}
    severity = 'CRITICAL' if name in critical else 'HIGH'
    message = {'event': name, 'severity': severity, 'account': event.get('account'), 'region': event.get('region'), 'time': d.get('eventTime'), 'actor': d.get('userIdentity', {}).get('arn'), 'source_ip': d.get('sourceIPAddress'), 'event_id': d.get('eventID')}
    arn = os.environ['SNS_TOPIC_ARN']
    boto3.client('sns', region_name=arn.split(':')[3]).publish(TopicArn=arn, Subject=f'{severity}: {name}'[:100], Message=json.dumps(message))
    return message
