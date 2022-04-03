import io
import sys
import boto3

import access_undenied_aws
import access_undenied_aws.analysis
import access_undenied_aws.cli
import access_undenied_aws.common
import access_undenied_aws.organizations

ACCESS_UNDENIED_ROLE = "accessUndenied"
ACCOUNT = "123456789012"
# BUCKET_NAME = "my-bucket-name"
# BUCKET_KEY = "scp_data.json"


def lambda_handler(event, context):
    config = access_undenied_aws.common.Config()
    config.session = boto3.Session()
    config.account_id = config.session.client("sts").get_caller_identity()["Account"]
    config.iam_client = config.session.client("iam")
    access_undenied_aws.cli.initialize_config_from_user_input(
        config=config,
        cross_account_role_name=(ACCESS_UNDENIED_ROLE),
        management_account_role_arn=(f"arn:aws:iam::{ACCOUNT}:role/{ACCESS_UNDENIED_ROLE}"),
        output_file=sys.stdout,
        suppress_output=True)
    with open('scp_data.json', 'r') as file:
        scp_data = file.read()
    access_undenied_aws.organizations.initialize_organization_data(
        config=config,
        scp_file_content=scp_data
    )
    result = access_undenied_aws.analysis.analyze(config, event)
    return {
        'statusCode': 200,
        'body': str(result)
    }
