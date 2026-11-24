import os, json, boto3

def lambda_handler(event, context):
    ec2=boto3.client('ec2')
    volumes=[v['VolumeId'] for page in ec2.get_paginator('describe_volumes').paginate(Filters=[{'Name':'status','Values':['available']}]) for v in page['Volumes']]
    addresses=[a['AllocationId'] for a in ec2.describe_addresses()['Addresses'] if a.get('AllocationId') and not a.get('AssociationId')]
    result={'unattached_volumes':volumes,'unassociated_eips':addresses}
    if (volumes or addresses) and os.getenv('SNS_TOPIC_ARN'):
        arn=os.environ['SNS_TOPIC_ARN']; boto3.client('sns',region_name=arn.split(':')[3]).publish(TopicArn=arn,Subject='Unused AWS resource candidates',Message=json.dumps(result))
    return result
