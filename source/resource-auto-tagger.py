import json
import logging
import boto3
import botocore
import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logging.getLogger().setLevel(logging.INFO)
log = logging.getLogger(__name__)

# Instantiate Boto3 clients & resources for every AWS service API called
iam_client = boto3.client("iam")
ec2_client = boto3.client("ec2")
ec2_resource = boto3.resource("ec2")

# Slack Client iInstantiation
slack_client = WebClient(token=os.environ.get("SLACK_BOT_TOKEN"))
aws_region = os.environ['AWS_REGION']

def get_iam_role_tags(role_name):
    try:
        response = iam_client.list_role_tags(RoleName=role_name)
        iam_tag_list = response.get("Tags")
        log.info(f"'IAM Role Tag List': {iam_tag_list}")
        return response.get("Tags")
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error:  {error}")
        return None


def get_iam_user_tags(iam_user_name):
    try:
        response = iam_client.list_user_tags(UserName=iam_user_name)
        iam_tag_list = response.get("Tags")
        log.info(f"'IAM User Tag List': {iam_tag_list}")
        return response.get("Tags")
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        return None

def send_slack_alerts(slack_alert_block, user_email):
    channel_id = '@' + user_email.split('@')[0]
    try:
    # Call the conversations.list method using the WebClient
        result = slack_client.chat_postMessage(
            channel=channel_id, blocks=slack_alert_block,
            text="Important: Non-Compliant EC2 Instance")
        log.info("'statusCode': 200")
        log.info(f"'Slack Response': {result}")
    except SlackApiError as error:
        log.error(f"Slack API returned error: {error}")


# Apply resource tags to EC2 instances & attached EBS volumes
def set_ec2_instance_attached_vols_tags(ec2_instance_id, resource_tags):
    try:
        response = ec2_client.create_tags(
            Resources=[ec2_instance_id], Tags=resource_tags
        )
        response = ec2_client.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [ec2_instance_id]}]
        )
        try:
            for volume in response.get("Volumes"):
                ec2_vol = ec2_resource.Volume(volume["VolumeId"])
                vol_tags = ec2_vol.create_tags(Tags=resource_tags)
            return True
        except botocore.exceptions.ClientError as error:
            log.error(f"Boto3 API returned error: {error}")
            log.error(f"No Tags Applied To: {volume['VolumeId']}")
            return False
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        log.error(f"No Tags Applied To: {ec2_instance_id}")
        return False


def cloudtrail_event_parser(event):
    returned_event_fields = {}

    # Check if an IAM user created these EC2 instances & get that user
    if event.get("detail").get("userIdentity").get("type") == "IAMUser":
        returned_event_fields["iam_user_name"] = (
            event.get("detail").get("userIdentity").get("userName", "")
        )

    # Get the assumed IAM role name used to create the new EC2 instance(s)
    if event.get("detail").get("userIdentity").get("type") == "AssumedRole":
        # Check if optional Cloudtrail sessionIssuer field indicates assumed role credential type
        # If so, extract the IAM role named used during EC2 instance creation
        if (
            event.get("detail")
            .get("userIdentity")
            .get("sessionContext")
            .get("sessionIssuer")
            .get("type")
            == "Role"
        ):
            role_arn = (
                event.get("detail")
                .get("userIdentity")
                .get("sessionContext")
                .get("sessionIssuer")
                .get("arn")
            )
            role_components = role_arn.split("/")
            returned_event_fields["role_name"] = role_components[-1]
            # Get the user ID who assumed the IAM role
            if event.get("detail").get("userIdentity").get("arn"):
                user_id_arn = event.get("detail").get("userIdentity").get("arn")
                user_id_components = user_id_arn.split("/")
                returned_event_fields["user_id"] = user_id_components[-1]
            else:
                returned_event_fields["user_id"] = ""
        else:
            returned_event_fields["role_name"] = ""

    # Extract & return the list of new EC2 instance(s) and their parameters
    returned_event_fields["instances_set"] = (
        event.get("detail").get("responseElements").get("instancesSet")
    )

    # Extract the date & time of the EC2 instance creation
    returned_event_fields["resource_date"] = event.get("detail").get("eventTime")

    return returned_event_fields

def get_iam_user_email_id(iam_user_name):
    try:
        response = iam_client.list_user_tags(UserName=iam_user_name)
        iam_tag_list = response.get("Tags")
        for tag in iam_tag_list:
            if tag['Key'] == 'Owner':
                log.info(f"'IAM User Email ID from IAM Tags': {tag['Value']}")
                return tag['Value']
    except botocore.exceptions.ClientError as error:
        log.error(f"Boto3 API returned error: {error}")
        return None


def lambda_handler(event, context):
    resource_tags = []
    user_email = False
    mandatory_tags = ['Name', 'Department', 'Project'] 
    instance_name = "Not Specified"
    ec2_instance_id = ''
    ec2_instance_name_block = "*EC2 Name:*  " + instance_name
    project_tag_allowed_values = " :white_small_square: *Project   : * DAI, HAIC, HAMC, Aquarium, POCPuddle, EnterprisePuddle, SnowflakePuddle, SparklingWater, Steam, MLOps, H2O3, H2OAutoML \n"
    department_tag_allowed_values = " :white_small_square:  *Department   : * Engineering, DataScience, ProductManagement, CustomerSuccess, SalesEngineering, SpecialOps \n"
    name_tag_allowed_values = " :white_small_square: *Name   :* Meaningful name to identify resource \n"
    mandory_tag_allowed_values = {'Project': project_tag_allowed_values, 'Department' : department_tag_allowed_values, 'Name':  name_tag_allowed_values}
    missing_mandatory_tag_allowed_values="*Missing Mandatory Tag keys and Allowed Values :* \n "
    owner_tag_filter=[{'Name': 'tag:Owner','Values': ['*']},{'Name': 'resource-id','Values': [ec2_instance_id]}]
    slack_alert_block = [
    		{
    			"type": "header",
    			"text": {
    				"type": "plain_text",
    				"text": ":alert: Insufficient Tag Alert!"
    			}
    		},
    		{
    			"type": "context",
    			"elements": [
    				{
    					"type": "plain_text",
    					"text": "The EC2 You just created does not have mandotory tags configured. \n All the EC2s without Mandatory Tags will be deleted within 3 days!"
    				}
    			]
    		},
    		{
    			"type": "section",
    			"text": {
    				"type": "mrkdwn",
    				"text": "<https://h2oai.atlassian.net/wiki/spaces/DEVOPS/pages/3620929755/H2O.AI+AWS+Account+Handling+User+Guidelines#Rules-and-Best-Practices|Please follow this guide when creating new AWS Resources>"
    			}
    		},
    		{
    			"type": "divider"
    		},
    		{
    			"type": "section",
    			"fields": [
    				{
    					"type": "mrkdwn",
    					"text": ec2_instance_name_block
    				}
    			]
    		},
    		{
    			"type": "section",
    			"text": {
    				"type": "mrkdwn",
    				"text": missing_mandatory_tag_allowed_values
    			}
    		},
    		{
    			"type": "divider"
    		},
    		{
    			"type": "section",
    			"text": {
    				"type": "mrkdwn",
    				"text": "Add missing tags "
    			},
    			"accessory": {
    				"type": "button",
    				"text": {
    					"type": "plain_text",
    					"text": "AWS Console EC2 Link"
    				},
    				"value": "click_me_123",
    				"style": "primary",
    				"url": 'instance_manage_tag_url',
    				"action_id": "button-action"
    			}
    		}
    	]

    # Parse the passed CloudTrail event and extract pertinent EC2 launch fields
    event_fields = cloudtrail_event_parser(event)

    # Check for IAM User initiated event & get any associated resource tags
    if event_fields.get("iam_user_name"):
        resource_tags.append(
            {"Key": "IAMUserName", "Value": event_fields["iam_user_name"]}
        )
        iam_user_resource_tags = get_iam_user_tags(event_fields["iam_user_name"])
        if iam_user_resource_tags:
            resource_tags += iam_user_resource_tags


    # Check for event date & time in returned CloudTrail event field
    # and append as resource tag
    if event_fields.get("resource_date"):
        resource_tags.append(
            {"Key": "Date created", "Value": event_fields["resource_date"]}
        )

    # Check for IAM assumed role initiated event & get any associated resource tags
    if event_fields.get("role_name"):
        resource_tags.append(
            {"Key": "IAMRoleName", "Value": event_fields["role_name"]}
        )
        iam_role_resource_tags = get_iam_role_tags(event_fields["role_name"])
        if iam_role_resource_tags:
            resource_tags += iam_role_resource_tags
        if event_fields.get("user_id"):
            resource_tags.append(
                {"Key": "User ID", "Value": event_fields["user_id"]}
            )
    # Tag EC2 instances listed in the CloudTrail event
    if event_fields.get("instances_set"):
        for item in event_fields.get("instances_set").get("items"):
            ec2_instance_id = item.get("instanceId")
            for tag in ec2_client.describe_tags( Filters = [{'Name': 'resource-id','Values': [ec2_instance_id]}] )['Tags']:
                log.info(f"'EC2 Tag List': {tag}")
                if tag['Key'] == "Name":
                    log.info(f"'EC2 Name from tags': {tag['Value']}")
                    slack_alert_block[4]['fields'][0]['text'] = "*EC2 Name:   *   " + tag['Value']
                if tag['Key'] in mandatory_tags:
                    mandatory_tags.remove(tag['Key'])  
                if tag['Key'] == 'Owner':
                    if tag['Value'].split('@')[1] == 'h2o.ai':
                        user_email = tag['Value']
                        log.info(f"'IAM User's Email ID from Tags' :{user_email}")
                # Checking for other mandatory tags  
            if mandatory_tags:
                log.info(f"'Missing Mandatory Tags' :{mandatory_tags}")
                for missing_tag in mandatory_tags:
                    missing_mandatory_tag_allowed_values += mandory_tag_allowed_values[missing_tag]
                slack_alert_block[5]['text']['text'] = missing_mandatory_tag_allowed_values
                slack_alert_block[7]['accessory']['url'] = "https://console.aws.amazon.com/ec2/v2/home?region=" + aws_region + "#ManageInstanceTags:instanceId=" + ec2_instance_id
                if user_email:
                    send_slack_alerts(slack_alert_block, user_email)
                else:
                    if set_ec2_instance_attached_vols_tags(ec2_instance_id, resource_tags):
                        log.info(f"'Tags List': {resource_tags}")
                        log.info("'statusCode': 200")
                        log.info(f"'Resource ID': {ec2_instance_id}")
                        log.info(f"'body': {json.dumps(resource_tags)}")
                        user_email=get_iam_user_email_id(event_fields["iam_user_name"])
                        if user_email:
                            send_slack_alerts(slack_alert_block, user_email)
                            log.info(f"'IAM User's Email ID from IAM Tags': {user_email}")
                    else:
                        log.info("'statusCode': 500")
                        log.info(f"'No tags applied to Resource ID': {ec2_instance_id}")
                        log.info(f"'Lambda function name': {context.function_name}")
                        log.info(f"'Lambda function version': {context.function_version}")
    else:
        log.info("'statusCode': 200")
        log.info(f"'No Amazon EC2 resources to tag': 'Event ID: {event.get('id')}'")
