import os, json, boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    findings = []
    for page in ec2.get_paginator('describe_security_groups').paginate():
        for group in page['SecurityGroups']:
            for rule in group.get('IpPermissions',[]):
                proto = rule['IpProtocol']
                ports = [p for p in (22,3389) if proto=='-1' or (proto in ('tcp','6') and rule.get('FromPort',65536)<=p<=rule.get('ToPort',-1))]
                public = any(r.get('CidrIp')=='0.0.0.0/0' for r in rule.get('IpRanges',[])) or any(r.get('CidrIpv6')=='::/0' for r in rule.get('Ipv6Ranges',[]))
                if ports and public: findings.append({'group_id':group['GroupId'],'ports':ports})
    if findings and os.getenv('SNS_TOPIC_ARN'):
        arn=os.environ['SNS_TOPIC_ARN']; boto3.client('sns',region_name=arn.split(':')[3]).publish(TopicArn=arn,Subject='Public SSH/RDP security groups',Message=json.dumps(findings[:100]))
    return {'findings':findings}
