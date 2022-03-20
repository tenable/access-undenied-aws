import json
import re
from typing import Optional

import boto3
import botocore
from aws_error_utils import errors

from access_undenied_aws import common
from access_undenied_aws import event_permission_data
from access_undenied_aws import logger


def _get_ecr_resource_policy(
        arn_match: re.Match,
        session: boto3.Session,
        region: str,
        resource: common.Resource,
) -> Optional[common.Policy]:
    repository_policy_response = session.client(
        "ecr", region_name=region
    ).get_repository_policy(repositoryName=(arn_match.group("resource_id")))
    return common.Policy(
        attachment_target_arn=repository_policy_response["ARN"],
        attachment_target_type="Resource: ECR Repository",
        policy_name="ECRRepositoryResourcePolicy",
        policy_arn="/".join([resource.arn, "ECRRepositoryResourcePolicy"]),
        policy_document=repository_policy_response["ResourcePolicy"],
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def _get_iam_resource_policy(
        session: boto3.Session, resource: common.Resource
) -> Optional[common.Policy]:
    resource_policy_document = json.dumps(
        session.client("iam").get_role(RoleName=resource.arn.split("/")[-1])["Role"][
            "AssumeRolePolicyDocument"
        ]
    )
    return common.Policy(
        attachment_target_arn=resource.arn,
        attachment_target_type="Resource: IAM Role",
        policy_name="RoleTrustPolicy",
        policy_arn="/".join([resource.arn, "RoleTrustPolicy"]),
        policy_document=resource_policy_document,
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def _get_kms_resource_policy(
        arn_match: re.Match,
        session: boto3.Session,
        region: str,
        resource: common.Resource,
) -> Optional[common.Policy]:
    key_policy_document = session.client("kms", region_name=region).get_key_policy(
        KeyId=(arn_match.group("resource_id")), PolicyName="default"
    )["Policy"]
    return common.Policy(
        attachment_target_arn=resource.arn,
        attachment_target_type="Resource: KMS Key",
        policy_name="KMSKeyPolicy",
        policy_arn="/".join([resource.arn, "KMSKeyPolicy"]),
        policy_document=key_policy_document,
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def _get_lambda_resource_policy(
        arn_match: re.Match,
        session: boto3.Session,
        region: str,
        resource: common.Resource,
) -> Optional[common.Policy]:
    lambda_function_policy_response = session.client(
        "lambda", region_name=region
    ).get_policy(FunctionName=(arn_match.group("resource_id")))
    return common.Policy(
        attachment_target_arn=arn_match.group(0),
        attachment_target_type="Resource: Lambda Function",
        policy_name="LambdaFunctionResourcePolicy",
        policy_arn="/".join([resource.arn, "LambdaFunctionResourcePolicy"]),
        policy_document=lambda_function_policy_response["Policy"],
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def _get_resource_account_session(config: common.Config, resource: common.Resource) -> boto3.Session:
    if resource.account_id == config.account_id:
        return config.session

    role_arn = f"arn:aws:iam::{resource.account_id}:role/{config.cross_account_role_name}"
    try:
        role_credentials = config.session.client("sts").assume_role(
            RoleArn=role_arn, RoleSessionName="AccessUndeniedResourceSession"
        )["Credentials"]
        return boto3.Session(
            aws_access_key_id=role_credentials["AccessKeyId"],
            aws_secret_access_key=role_credentials["SecretAccessKey"],
            aws_session_token=role_credentials["SessionToken"],
        )
    except botocore.exceptions.ClientError as client_error:
        logger.error(
            f"Could not assume resource account role: {role_arn}:" f" {str(client_error)}"
        )
        raise common.AccessUndeniedError(
            f"[Error:{str(client_error)}] assuming [role_arn:{role_arn}] in the"
            f" resource account of [resource_arn={resource.arn}] when getting"
            " the resource policy.",
            common.AccessDeniedReason.ERROR,
        )


def _get_s3_resource_policy(
        arn_match: re.Match, session: boto3.Session, resource: common.Resource
) -> Optional[common.Policy]:
    bucket_name = arn_match.group("resource_type") or arn_match.group("resource_id")
    s3_client = session.client("s3")
    try:
        bucket_policy_document = s3_client.get_bucket_policy(Bucket=bucket_name)["Policy"]
    except errors.NoSuchBucketPolicy:
        bucket_policy_document = EMPTY_RESOURCE_POLICY.format(resource=resource.arn)
    return common.Policy(
        attachment_target_arn=resource.arn,
        attachment_target_type="Resource: S3 Bucket",
        policy_name="S3BucketPolicy",
        policy_arn="/".join([resource.arn, "S3BucketPolicy"]),
        policy_document=bucket_policy_document,
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def _get_secretsmanager_resource_policy(
        arn_match: re.Match,
        session: boto3.Session,
        region: str,
        resource: common.Resource,
) -> Optional[common.Policy]:
    secretsmanager_client = session.client("secretsmanager", region_name=region)
    secret_policy_response = secretsmanager_client.get_resource_policy(
        SecretId=(arn_match.group("resource_id"))
    )
    return common.Policy(
        attachment_target_arn=secret_policy_response["ARN"],
        attachment_target_type="Resource: SecretsManager Secret",
        policy_name="SecretResourcePolicy",
        policy_arn="/".join([resource.arn, "SecretResourcePolicy"]),
        policy_document=secret_policy_response["ResourcePolicy"],
        policy_type=common.PolicyType.RESOURCE_POLICY,
    )


def get_resource_policy(
        config: common.Config,
        event_permission_data_: event_permission_data.EventPermissionData,
        region: str,
) -> Optional[common.Policy]:
    if "*" in event_permission_data_.resource.arn:
        return None

    arn_match = re.search(
        common.RESOURCE_ARN_PATTERN,
        event_permission_data_.resource.arn,
        re.IGNORECASE,
    )
    if arn_match:
        service_name = arn_match.group("service")
    else:
        service_name = event_permission_data_.iam_permission.split(":")[0]
        if service_name != "secretsmanager":
            logger.warning(
                "Unable to parse service name from resource"
                f" [resource:{event_permission_data_.resource.arn}]"
                " ignoring resource policy..."
            )
            return None
    resource_account_session = _get_resource_account_session(config, event_permission_data_.resource)
    try:
        if service_name == "iam" and event_permission_data_.iam_permission in [
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
        ]:
            return _get_iam_resource_policy(
                resource_account_session, event_permission_data_.resource
            )
        if service_name == "s3":
            return _get_s3_resource_policy(
                arn_match,
                resource_account_session,
                event_permission_data_.resource,
            )
        if service_name == "kms" and arn_match.group("resource_type") == "key":
            return _get_kms_resource_policy(
                arn_match,
                resource_account_session,
                region,
                event_permission_data_.resource,
            )
        if service_name == "secretsmanager":
            return _get_secretsmanager_resource_policy(
                arn_match,
                config.session,
                region,
                event_permission_data_.resource,
            )
        if service_name == "ecr":
            return _get_ecr_resource_policy(
                arn_match,
                config.session,
                region,
                event_permission_data_.resource,
            )
        if service_name == "lambda":
            return _get_lambda_resource_policy(
                arn_match,
                config.session,
                region,
                event_permission_data_.resource,
            )
    except botocore.exceptions.ClientError as client_error:
        raise common.AccessUndeniedError(
            f"[Error:{str(client_error)}] Getting resource policy for"
            f" [resource_arn={event_permission_data_.resource.arn}]",
            common.AccessDeniedReason.ERROR,
        )
    logger.warning(
        f"Service [service_name:{service_name}] does not have resource policy"
        " support in AccessUndenied, ignoring resource policy..."
    )
    return None


EMPTY_RESOURCE_POLICY = """
  {{
    "Version": "2012-10-17",
    "Statement": [
      {{
        "Effect": "Allow",
        "NotPrincipal": "*",
        "NotAction": "*",
        "Resource": "{resource}"
      }}
    ]
  }}
"""
