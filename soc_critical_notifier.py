import os, json, boto3
from boto3.dynamodb.types import TypeDeserializer

def lambda_handler(event, context):
    arn = os.environ['SNS_TOPIC_ARN']
    sns = boto3.client('sns',region_name=arn.split(':')[3])
    decoder = TypeDeserializer()
    count = 0
    for record in event['Records']:
        if record['eventName'] != 'INSERT': continue
        item = {k:decoder.deserialize(v) for k,v in record['dynamodb']['NewImage'].items()}
        if item.get('severity') != 'CRITICAL': continue
        msg = {k:item.get(k) for k in ('finding_id','title','source','severity','timestamp','account')}
        sns.publish(TopicArn=arn,Subject='CRITICAL AWS security finding',Message=json.dumps(msg,default=str))
        count += 1
    return {'published':count}
