import os, json, boto3
from datetime import datetime, timedelta, timezone
from soc_findings_ingestion import store

WATCH = {'CreateAccessKey','UpdateAssumeRolePolicy','AttachRolePolicy','PutRolePolicy','StopLogging','DeleteTrail','DeactivateMFADevice','SetDefaultPolicyVersion','AssumeRole'}
def lambda_handler(event, context):
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=int(os.getenv('LOOKBACK_MINUTES','15')))
    count = 0
    for region in os.getenv('REGIONS',os.environ['AWS_REGION']).split(','):
        client = boto3.client('cloudtrail',region_name=region.strip())
        for page in client.get_paginator('lookup_events').paginate(StartTime=start,EndTime=end):
            for row in page['Events']:
                if row['EventName'] not in WATCH: continue
                d = json.loads(row['CloudTrailEvent'])
                if d.get('errorCode'): continue
                root = d.get('userIdentity',{}).get('type') == 'Root'
                severity = 'CRITICAL' if root or row['EventName'] in {'StopLogging','DeleteTrail'} else 'MEDIUM' if row['EventName']=='AssumeRole' else 'HIGH'
                count += store({'finding_id':'cloudtrail-'+row['EventId'],'source':'cloudtrail','severity':severity,'title':row['EventName'],'timestamp':row['EventTime'].isoformat(),'account':d.get('recipientAccountId',''),'region':region,'actor':d.get('userIdentity',{}).get('arn','')})
    return {'inserted':count}
