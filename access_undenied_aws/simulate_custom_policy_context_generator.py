from __future__ import annotations

from typing import (
    Dict,
    List,
    Callable,
    Sequence,
    TYPE_CHECKING,
    Optional,
    Iterable,
)

import boto3
import botocore.exceptions

from access_undenied_aws import event
from access_undenied_aws import event_permission_data
from access_undenied_aws import logger

if TYPE_CHECKING:
    from mypy_boto3_iam.type_defs import ContextEntryTypeDef
else:
    ContextEntryTypeDef = object


class SimulateCustomPolicyContextGenerator(object):
    def __init__(
        self,
        session: boto3.Session,
        event_permission_data_: event_permission_data.EventPermissionData,
        cloudtrail_event_: event.Event,
    ):
        self.session = session
        self.iam_client = session.client("iam")
        self.event_permission_data = event_permission_data_
        self.cloudtrail_event = cloudtrail_event_

    def _get_aws_event_time(self) -> Optional[ContextEntryTypeDef]:
        return {
            "ContextKeyName": "aws:CurrentTime",
            "ContextKeyValues": (self.cloudtrail_event.event_time,),
            "ContextKeyType": "string",
        }

    def _get_aws_principal_arn(self) -> Optional[ContextEntryTypeDef]:
        return {
            "ContextKeyName": "aws:PrincipalArn",
            "ContextKeyValues": (self.event_permission_data.principal.arn,),
            "ContextKeyType": "string",
        }

    def _get_aws_principal_arn_caps(self) -> Optional[ContextEntryTypeDef]:
        context_entry = {
            "ContextKeyName": "aws:PrincipalARN",
            "ContextKeyValues": (self.event_permission_data.principal.arn,),
            "ContextKeyType": "string",
        }
        return context_entry

    def _get_aws_principal_tag(self, tag_key: str) -> Optional[ContextEntryTypeDef]:
        principal_tags = []
        try:
            if self.event_permission_data.principal.type == "AssumedRole":
                principal_tags = self.iam_client.list_role_tags(
                    RoleName=(self.event_permission_data.principal.name)
                )["Tags"]
            elif self.event_permission_data.principal.type == "IAMUser":
                principal_tags = self.iam_client.list_user_tags(
                    UserName=(self.event_permission_data.principal.name)
                )["Tags"]
        except botocore.exceptions.ClientError as list_tags_error:
            logger.error(
                f"[Error:{repr(list_tags_error)}] when getting" " aws:PrincipalTag value"
            )
            return None
        for tag in principal_tags:
            if tag["Key"] == tag_key:
                return {
                    "ContextKeyName": f"aws:PrincipalTag/{tag_key}",
                    "ContextKeyValues": (tag["Value"],),
                    "ContextKeyType": "string",
                }
        return None

    def _get_aws_requested_region(self) -> Optional[ContextEntryTypeDef]:
        if not self.cloudtrail_event.region:
            return None

        return {
            "ContextKeyName": "aws:RequestedRegion",
            "ContextKeyValues": (self.cloudtrail_event.region,),
            "ContextKeyType": "string",
        }

    def _get_aws_service_name(self) -> Optional[ContextEntryTypeDef]:
        if not self.cloudtrail_event.event_source:
            return None

        return {
            "ContextKeyName": "iam:AWSServiceName",
            "ContextKeyValues": (self.cloudtrail_event.event_source,),
            "ContextKeyType": "string",
        }

    def _get_aws_source_ip(self) -> Optional[ContextEntryTypeDef]:
        if not self.cloudtrail_event.source_ip_address:
            return None

        return {
            "ContextKeyName": "aws:SourceIp",
            "ContextKeyValues": (self.cloudtrail_event.source_ip_address,),
            "ContextKeyType": "string",
        }

    def _get_aws_source_vpce(self) -> Optional[ContextEntryTypeDef]:
        if not self.cloudtrail_event.vpc_endpoint_id:
            return None

        return {
            "ContextKeyName": "aws:sourceVpce",
            "ContextKeyValues": (self.cloudtrail_event.vpc_endpoint_id,),
            "ContextKeyType": "string",
        }

    def _get_aws_username(self) -> Optional[ContextEntryTypeDef]:
        return {
            "ContextKeyName": "aws:username",
            "ContextKeyValues": (self.event_permission_data.principal.name,),
            "ContextKeyType": "string",
        }

    def generate_context(
        self, context_keys: Iterable[str]
    ) -> Sequence[ContextEntryTypeDef]:
        context_entries = []
        for context_key in context_keys:
            context_generation_result = None
            if (
                context_key in SimulateCustomPolicyContextGenerator.KEY_FUNCTION_DICT
                or context_key
                in SimulateCustomPolicyContextGenerator.KEY_WITH_SUBKEY_FUNCTION_DICT
            ):
                context_generation_result = (
                    SimulateCustomPolicyContextGenerator.KEY_FUNCTION_DICT[context_key](
                        self
                    )
                )
            elif (
                context_key
                in SimulateCustomPolicyContextGenerator.KEY_WITH_SUBKEY_FUNCTION_DICT
                and "/" in context_key
            ):
                subkey = context_key.split("/", 1)[1]
                context_generation_result = (
                    SimulateCustomPolicyContextGenerator.KEY_WITH_SUBKEY_FUNCTION_DICT[
                        context_key
                    ](self, subkey)
                )
            if context_generation_result:
                context_entries.append(context_generation_result)
            else:
                logger.warning(
                    "Unable to find value for condition context key"
                    f" [context_key: {context_key}]"
                )
        return context_entries

    KEY_FUNCTION_DICT: Dict[
        str,
        Callable[
            [SimulateCustomPolicyContextGenerator],
            Optional[ContextEntryTypeDef],
        ],
    ] = {
        "aws:username": _get_aws_username,
        "aws:CurrentTime": _get_aws_event_time,
        "aws:PrincipalArn": _get_aws_principal_arn,
        "aws:PrincipalARN": _get_aws_principal_arn_caps,
        "aws:SourceVpce": _get_aws_source_vpce,
        "aws:SourceIp": _get_aws_source_ip,
        "aws:RequestedRegion": _get_aws_requested_region,
        "iam:AWSServiceName": _get_aws_service_name,
    }

    KEY_WITH_SUBKEY_FUNCTION_DICT: Dict[
        str,
        Callable[
            [SimulateCustomPolicyContextGenerator, str],
            Optional[ContextEntryTypeDef],
        ],
    ] = {
        "aws:PrincipalTag": _get_aws_principal_tag,
    }
