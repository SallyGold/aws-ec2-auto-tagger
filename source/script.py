import boto3
#
client = boto3.client("ec2")
#response = client.describe_tags(
#    Filters=[
#        {
#            'Name': 'tag:Owner'
#        },
#        {
#            'Name': 'resource-id',
#            'Values': [
#                'i-0ed3abe3f19635e39'
#            ]
#        }
#    ]
#)
#
#res2 = client.describe_tags(
#    Filters=[
#        {
#            'Name': 'resource-id',
#            'Values': [
#                'i-0ed3abe3f19635e39'
#            ]
#        }
#    ]
#)
#
#res3 = client.describe_tags(
#    Filters=[
#        {
#            'Name': 'tag:Owner'
#        }
#    ]
#)
#custom_filter = [{'Name':'tag:Owner', 'Values': ['*']}]
#resss = client.describe_instances(Filters=custom_filter,InstanceIds=['i-0d2f14227d1172f49'])
#
#
#
##print(res3)
##print(response)
##print(res2)
##print(resss)
##print(resss)
#
#if resss:
#    print('Yes')
#else:
#    print('Nooo')
#

response = client.describe_tags(
    Filters=[
        {
            'Name': 'tag:Owner',
            'Values': [
                '*'
            ]
        },
        {
            'Name': 'resource-id',
            'Values': [
                'i-0e90f2f3bd7811cb2'
            ]
        }
    ]
)

print(response['Tags'])


response2 = client.describe_tags(
    Filters=[
        {
            'Name': 'tag:Owner',
            'Values': [
                '*'
            ]
        },
        {
            'Name': 'resource-id',
            'Values': [
                'i-0d2f14227d1172f49'
            ]
        }
    ]
)
print(response2['Tags'])


if client.describe_tags( Filters=[{'Name': 'tag:Owner','Values': ['*']},{'Name': 'resource-id','Values': ['i-0d2f14227d1172f49']}])['Tags']:
    print("this should not be printed")

if client.describe_tags( Filters=[{'Name': 'tag:Owner','Values': ['*']},{'Name': 'resource-id','Values': ['i-0e90f2f3bd7811cb2']}])['Tags']:
    print("this should be printed")

    Filters=[{'Name': 'tag:Owner','Values': ['*']},{'Name': 'resource-id','Values': ['i-0d2f14227d1172f49']}]
