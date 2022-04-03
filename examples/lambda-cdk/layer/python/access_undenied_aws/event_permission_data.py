from __future__ import annotations

import json
import re
from typing import Optional

import boto3
import botocore.exceptions
import pkg_resources

from access_undenied_aws import event
from access_undenied_aws import common
from access_undenied_aws import logger
from access_undenied_aws import utils

ACCESS_DENIED_MESSAGES = json.load(
    open(
        pkg_resources.resource_filename(
            __name__, "definitions/access_denied_message_patterns.json"
        ),
        "r",
    )
)

IAM_DATASET_MAPPINGS = json.load(
    open(pkg_resources.resource_filename(__name__, "definitions/map.json"), "r")
)


class EventPermissionData(object):
    def __init__(self) -> None:
        self.principal: common.Principal = common.Principal()
        self.iam_permission: str = ""
        self.resource: Optional[common.Resource] = None
        self.encoded_message: str = ""
        self.sdk_service_action: str = ""
        self.is_missing_allow_in_identity_based_policy = False

    @classmethod
    def from_event(
        cls,
        cloudtrail_event_: event.Event,
        config: common.Config,
    ) -> EventPermissionData:
        event_permission_data_ = cls()
        event_permission_data_.principal = _get_principal_from_user_identity(
            cloudtrail_event_, config
        )
        event_permission_data_._parse_error_message(cloudtrail_event_)
        if not event_permission_data_.iam_permission:
            event_permission_data_.iam_permission = (
                event_permission_data_._parse_iam_permission(cloudtrail_event_)
            )
        if not event_permission_data_.resource:
            event_permission_data_._parse_resource_from_cloudtrail_event(
                cloudtrail_event_
            )
        if not event_permission_data_.resource:
            event_permission_data_._parse_resource_from_iam_dataset_mapping(
                cloudtrail_event_
            )
        if not event_permission_data_.resource:
            event_permission_data_._parse_resource_from_common_request_parameters(
                cloudtrail_event_
            )
        if not event_permission_data_.resource:
            logger.debug(
                "Unable to parse resource field for"
                f" {cloudtrail_event_.event_source}:{cloudtrail_event_.event_name},"
                " setting '*' as default value."
            )
            event_permission_data_.resource = common.Resource(
                arn="*",
                account_id=event_permission_data_.principal.account_id,
            )
        return event_permission_data_

    def _parse_error_message(self, cloudtrail_event_: event.Event) -> None:
        if not cloudtrail_event_.error_message:
            return
        for access_denied_message_pattern in ACCESS_DENIED_MESSAGES[
            "invalidActionMessages"
        ]:
            if re.fullmatch(
                access_denied_message_pattern,
                cloudtrail_event_.error_message,
                re.IGNORECASE,
            ):
                raise common.AccessUndeniedError(
                    cloudtrail_event_.error_message,
                    common.AccessDeniedReason.INVALID_ACTION,
                )
        for access_denied_message_pattern in ACCESS_DENIED_MESSAGES[
            "accessDeniedMessages"
        ]:
            match = re.fullmatch(
                access_denied_message_pattern,
                cloudtrail_event_.error_message,
                re.IGNORECASE,
            )
            if not match:
                continue
            self.iam_permission = utils.get_regex_match_group_or_none(
                match, "iamPermission"
            )
            self._set_resource_parameter_from_error_message_match(match)
            self.is_missing_allow_in_identity_based_policy = (
                utils.get_regex_match_group_or_none(match, "missingAllowPolicyType")
                == "identity-based"
            )
            return
        logger.warning(
            "Unsupported AccessDenied message [ErrorMessage:"
            f" {cloudtrail_event_.error_message}]"
        )

    def _parse_iam_permission(self, cloudtrail_event_: event.Event) -> str:
        service_endpoint_name = cloudtrail_event_.event_source.split(".")[0]
        truncated_event_name = cloudtrail_event_.event_name.split("20")[0].split("V1")[0]
        sdk_service_names = IAM_DATASET_MAPPINGS["service_sdk_mappings"].get(
            service_endpoint_name
        ) or [service_endpoint_name]
        if service_endpoint_name not in IAM_DATASET_MAPPINGS["service_sdk_mappings"]:
            logger.warning(
                "Unidentified API service name [service_endpoint:"
                f" {service_endpoint_name}] from [event_source:"
                f" {cloudtrail_event_.event_source}], proceeding with the"
                f" service as [service_endpoint: {service_endpoint_name}]"
            )
        for sdk_service_name in sdk_service_names:
            sdk_service_action = f"{sdk_service_name}.{truncated_event_name}"
            if sdk_service_action in IAM_DATASET_MAPPINGS["sdk_permissionless_actions"]:
                raise common.AccessUndeniedError(
                    f"Permissionless action {sdk_service_action} cannot be" " denied.",
                    common.AccessDeniedReason.INVALID_ACTION,
                )
            if sdk_service_action in IAM_DATASET_MAPPINGS["sdk_method_iam_mappings"]:
                self.sdk_service_action = sdk_service_action
                action_from_mapping = IAM_DATASET_MAPPINGS["sdk_method_iam_mappings"][
                    sdk_service_action
                ][0]["action"]
                logger.debug(
                    "Got IAM permission from SDK->IAM mapping [iam_permission:"
                    f" {action_from_mapping}]..."
                )
                return action_from_mapping  # only the first permission

        logger.warning(
            "Unidentified API action"
            f" [sdk_service_names:{sdk_service_names}]:[action:{truncated_event_name}],"
            " proceeding with the IAM permission as"
            f" {service_endpoint_name}:{truncated_event_name}"
        )
        return f"{service_endpoint_name}:{truncated_event_name}"

    def _parse_resource_from_iam_dataset_mapping(
        self, cloudtrail_event_: event.Event
    ) -> None:
        if self.sdk_service_action not in IAM_DATASET_MAPPINGS["sdk_method_iam_mappings"]:
            return
        for iam_dataset_mapping_key, iam_dataset_mapping in IAM_DATASET_MAPPINGS[
            "sdk_method_iam_mappings"
        ][self.sdk_service_action][0]["resource_mappings"].items():
            logger.info(f"{iam_dataset_mapping_key}, {iam_dataset_mapping}")
            if "template" not in iam_dataset_mapping:
                continue
            template = iam_dataset_mapping["template"]
            # simple iam-dataset template: e.g. "template": "${RoleName}"
            resource_template_match = re.fullmatch(r"\${([^}]+)}", template)
            if not resource_template_match:
                continue
            if not cloudtrail_event_.raw_request_parameters:
                continue
            for (
                request_parameter,
                value,
            ) in cloudtrail_event_.raw_request_parameters.items():
                if request_parameter == resource_template_match.group(1):
                    if re.fullmatch(common.RESOURCE_ARN_PATTERN, value):
                        self.resource = common.Resource(
                            arn=value,
                            account_id=_parse_account_id_from_arn(
                                arn=value, default=self.principal.account_id
                            ),
                        )

    def _parse_resource_from_cloudtrail_event(
        self, cloudtrail_event_: event.Event
    ) -> None:
        for raw_resource in utils.get_iterable(cloudtrail_event_.raw_resources):
            for arn_key in ["arn", "Arn", "ARN"]:
                if arn_key in raw_resource:
                    # account id is the fourth element of arn:partition:service:region:account-id:resource
                    self.resource = common.Resource(
                        arn=raw_resource[arn_key],
                        account_id=(
                            raw_resource.get("accountId")
                            or _parse_account_id_from_arn(
                                arn=raw_resource[arn_key],
                                default=self.principal.account_id,
                            )
                        ),
                    )

    def _parse_resource_from_common_request_parameters(
        self, cloudtrail_event_: event.Event
    ) -> None:
        if cloudtrail_event_.raw_request_parameters:
            for resource_key in ["resource-arn", "id_"]:
                if resource_key not in cloudtrail_event_.raw_request_parameters:
                    continue
                resource_arn = cloudtrail_event_.raw_request_parameters[resource_key]
                self.resource = common.Resource(
                    arn=resource_arn,
                    account_id=_parse_account_id_from_arn(
                        arn=resource_arn, default=self.principal.account_id
                    ),
                )

    def _set_resource_parameter_from_error_message_match(
        self, error_message_regex_match: re.Match
    ) -> None:
        raw_resource_from_error_message = utils.get_regex_match_group_or_none(
            error_message_regex_match, "resource"
        )
        # ordinary resource arn with optional resource-type field
        # example 1: arn:aws:ec2:us-east-2:123456789012:instance/i-1234567812345678
        # example 2: arn:aws:s3:::my-bucket
        if raw_resource_from_error_message and re.match(
            r"^arn:[^:\n]*:[^:\n]*:[^:\n]*:[^:\n]*:(([^:/\n]*)[:/])?(.*)$",
            raw_resource_from_error_message,
        ):
            # account id is the fourth element of arn:partition:service:region:account-id:resource
            self.resource = common.Resource(
                raw_resource_from_error_message,
                _parse_account_id_from_arn(
                    raw_resource_from_error_message,
                    default=self.principal.account_id,
                ),
            )
            return

        raw_access_key_id_from_error_message = utils.get_regex_match_group_or_none(
            error_message_regex_match, "accessKeyId"
        )
        if raw_access_key_id_from_error_message:
            self.resource = common.Resource(
                arn=raw_access_key_id_from_error_message,
                account_id=self.principal.account_id,
            )
            return

        raw_role_name_from_error_message = utils.get_regex_match_group_or_none(
            error_message_regex_match, "roleName"
        )
        if raw_role_name_from_error_message:
            self.resource = common.Resource(
                arn=f"arn:aws:iam::{self.principal.account_id}:role/{raw_role_name_from_error_message}",
                account_id=self.principal.account_id,
            )
        return


def _get_principal_from_user_identity(
    event_: event.Event,
    config: common.Config,
) -> common.Principal:
    principal = common.Principal()
    principal.type = event_.principal_type
    if event_.principal_type == "IAMUser":
        principal.arn = principal.session_name = event_.raw_principal["arn"]
        principal.name = _get_principal_name_from_principal_arn(principal.arn)
        principal.account_id = _parse_account_id_from_arn(principal.arn)
        return principal

    if event_.principal_type == "AssumedRole":
        principal.arn = event_.raw_principal["sessionContext"]["sessionIssuer"]["arn"]
        principal.name = _get_principal_name_from_principal_arn(principal.arn)
        principal.session_name = event_.raw_principal["arn"]
        principal.account_id = _parse_account_id_from_arn(principal.arn)
        return principal

    if event_.principal_type == "AWSAccount":
        if event_.raw_principal["accountId"] == "ANONYMOUS_PRINCIPAL":
            raise common.AccessUndeniedError(
                "Anonymous principal access not yet supported.",
                common.AccessDeniedReason.ERROR,
            )
        # Handle the different behavior with a cross-account identity performing the action
        # in this case there is no principal ARN and we need to figure it out from the unique identifier
        # (AROAXXXX or AKIAXXX).
        # https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/
        # Example:
        # "userIdentity": {
        #     "accountId": "123456789012",
        #     "principalId": "AROA6C17283581726ASDFAS:role-session-name",
        #     "type": "AWSAccount"
        # }
        logger.debug("Cross-account access: Principal represented as unique id...")
        principal.arn = _get_principal_arn_from_cross_account_principal_id(
            config.cross_account_role_name,
            event_.raw_principal["principalId"],
            event_.raw_principal["accountId"],
        )
        principal.type = "AssumedRole"
        principal.name = _get_principal_name_from_principal_arn(principal.arn)
        principal.session_name = principal.arn
        principal.account_id = event_.raw_principal["accountId"]
        return principal

    if event_.principal_type == "AWSService":
        raise common.AccessUndeniedError(
            "AWS Service actions not yet supported.",
            common.AccessDeniedReason.ERROR,
        )

    failed_to_analyze_raw_principal_message = (
        "Could not parse user identity data into a principal,"
        " this could be because analyzing root user actions"
        " is not yet supported. [userIdentityData:"
        f" {event_.raw_principal}."
    )
    logger.error(failed_to_analyze_raw_principal_message)
    raise common.AccessUndeniedError(
        failed_to_analyze_raw_principal_message,
        common.AccessDeniedReason.ERROR,
    )


def _get_principal_arn_from_cross_account_principal_id(
    config: common.Config,
    raw_principal_id: str,
    account_id: str,
) -> str:
    # Example: "AROA6C17283581726ASDFAS:role-session-name"
    principal_unique_id = raw_principal_id.split(":")[0]
    logger.debug(
        "Retrieving principal arn for cross-account for [principal_unique_id:"
        f" {principal_unique_id}]"
    )
    if config.account_id == account_id:
        iam_client = config.iam_client
    else:
        try:
            role_credentials = config.session.client("sts").assume_role(
                RoleArn=f"arn:aws:iam::{config.account_id}:role/{config.cross_account_role_name}",
                RoleSessionName=f"AccessUndeniedCrossAccount_{account_id}",
            )
            target_account_session = boto3.Session(
                aws_access_key_id=role_credentials["Credentials"]["AccessKeyId"],
                aws_secret_access_key=role_credentials["Credentials"]["SecretAccessKey"],
                aws_session_token=role_credentials["Credentials"]["SessionToken"],
            )
            iam_client = target_account_session.client("iam")
        except botocore.exceptions.ClientError:
            raise common.AccessUndeniedError(
                message=(
                    f"Could not assume role into account {account_id} while"
                    " parsing unique id"
                    f" [raw_principal_id={principal_unique_id}]."
                ),
                access_denied_reason=common.AccessDeniedReason.ERROR,
            )
    try:
        if principal_unique_id.startswith("AROA"):
            for page in iam_client.get_paginator("list_roles").paginate(
                PaginationConfig={"PageSize": 25}
            ):
                for role in page.get("Roles"):
                    if role["RoleId"] == principal_unique_id:
                        return role["Arn"]
        elif principal_unique_id.startswith("AIDA"):
            for page in iam_client.get_paginator("list_users").paginate(
                PaginationConfig={"PageSize": 25}
            ):
                for user in page.get("Users"):
                    if user["UserId"] == principal_unique_id:
                        return user["Arn"]
        else:
            raise common.AccessUndeniedError(
                f"Unknown unique id type for {principal_unique_id}",
                common.AccessDeniedReason.ERROR,
            )
    except botocore.exceptions.ClientError:
        raise common.AccessUndeniedError(
            "Could not list roles/users while parsing AROA in account" f" {account_id}",
            common.AccessDeniedReason.ERROR,
        )
    raise common.AccessUndeniedError(
        "Could not parse unique id into role arn",
        common.AccessDeniedReason.ERROR,
    )


def _get_principal_name_from_principal_arn(principal: str) -> str:
    # Regex for role/user/group arn, capturing only the principal name parameter
    principal_name_match = re.fullmatch(
        r"^arn:aws:iam::\d{12}:(?:user|role|group)/(?:[^\s/:]+/)*([^\s/:]+)$",
        principal,
        re.IGNORECASE,
    )
    if principal_name_match:
        return principal_name_match.group(1)
    raise ValueError(f"unable to retrieve name for target: {principal}")


def _parse_account_id_from_arn(arn: str, default="") -> str:
    # regex for matching account id from arn.
    # Example: arn:aws:kms:us-east-1:123456789012:[.....]
    account_id_match = re.fullmatch(
        r"arn:aws:[^:]*:[^:]*:(\d{12}|):[^\s]+", arn, re.IGNORECASE
    )
    if account_id_match:
        return account_id_match.group(1) or default
    raise common.AccessUndeniedError(
        f"Could not parse account number from [arn: {arn}]",
        common.AccessDeniedReason.ERROR,
    )
