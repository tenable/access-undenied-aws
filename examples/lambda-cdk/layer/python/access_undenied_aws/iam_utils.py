import boto3
import botocore
import cachetools
from cachetools import keys
import collections.abc
import json
from typing import List, TYPE_CHECKING, Optional, Union, Iterable

from access_undenied_aws import common
from access_undenied_aws import logger

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iam.type_defs import (
        AttachedPolicyTypeDef,
        AttachedPermissionsBoundaryTypeDef,
        GetUserPolicyResponseTypeDef,
        GetGroupPolicyResponseTypeDef,
        GetRolePolicyResponseTypeDef,
    )
else:
    IAMClient = object
    AttachedPolicyTypeDef = object
    AttachedPermissionsBoundaryTypeDef = object
    GetUserPolicyResponseTypeDef = object
    GetGroupPolicyResponseTypeDef = object
    GetRolePolicyResponseTypeDef = object

InlinePolicyResponseTypeDef = Union[
    GetUserPolicyResponseTypeDef,
    GetGroupPolicyResponseTypeDef,
    GetRolePolicyResponseTypeDef,
]


def _create_policy_from_inline_policy_response(
    inline_policy_response: InlinePolicyResponseTypeDef,
    attachment_target_arn: str,
    attachment_target_type: common.AttachmentTargetType,
) -> common.Policy:
    # For some reason the get_(role|user|group)_policy API does not behave
    # according to the type hints, this line fixes that.
    inline_policy_document = (
        inline_policy_response["PolicyDocument"]
        if isinstance(inline_policy_response["PolicyDocument"], str)
        else json.dumps(inline_policy_response["PolicyDocument"])
    )
    return common.Policy(
        attachment_target_arn=attachment_target_arn,
        attachment_target_type=attachment_target_type,
        policy_name=inline_policy_response["PolicyName"],
        policy_arn="/".join(
            [attachment_target_arn, inline_policy_response["PolicyName"]]
        ),
        policy_document=inline_policy_document,
        policy_type=common.PolicyType.IDENTITY_INLINE_POLICY,
    )


def _create_policy_from_managed_policy_response(
    iam_client: IAMClient,
    managed_policy_response: AttachedPolicyTypeDef,
    attachment_target_arn: str,
    attachment_target_type: common.AttachmentTargetType,
) -> common.Policy:
    return common.Policy(
        attachment_target_arn=attachment_target_arn,
        attachment_target_type=attachment_target_type,
        policy_name=managed_policy_response["PolicyName"],
        policy_arn=managed_policy_response["PolicyArn"],
        policy_document=_get_policy_document_default_version_from_policy_arn(
            iam_client, managed_policy_response["PolicyArn"]
        ),
        policy_type=common.PolicyType.IDENTITY_MANAGED_POLICY,
    )


def _create_policy_from_permissions_boundary_response(
    iam_client: IAMClient,
    permission_boundary_response: AttachedPermissionsBoundaryTypeDef,
    attachment_target_arn: str,
    attachment_target_type: common.AttachmentTargetType,
) -> common.Policy:
    return common.Policy(
        attachment_target_arn=attachment_target_arn,
        attachment_target_type=attachment_target_type,
        policy_name=permission_boundary_response["PermissionsBoundaryArn"].split("/")[-1],
        policy_arn=permission_boundary_response["PermissionsBoundaryArn"],
        policy_document=_get_policy_document_default_version_from_policy_arn(
            iam_client,
            permission_boundary_response["PermissionsBoundaryArn"],
        ),
        policy_type=common.PolicyType.PERMISSIONS_BOUNDARY_POLICY,
    )


def _get_cross_account_iam_client(
    target_account: str, session: boto3.Session, cross_account_role_name: str
) -> IAMClient:
    try:
        role_credentials = session.client("sts").assume_role(
            RoleArn=(f"arn:aws:iam::{target_account}:role/{cross_account_role_name}"),
            RoleSessionName="AccessUndeniedResourceSession",
        )
        return boto3.Session(
            aws_access_key_id=role_credentials["Credentials"]["AccessKeyId"],
            aws_secret_access_key=role_credentials["Credentials"]["SecretAccessKey"],
            aws_session_token=role_credentials["Credentials"]["SessionToken"],
        ).client("iam")
    except botocore.exceptions.ClientError as client_error:
        msg = (
            "Could not assume cross-account role: [role_arn: "
            f"arn:aws:iam::{target_account}:role/{cross_account_role_name}]."
            f" [Error: {repr(client_error)}]."
        )
        logger.error(msg)
        raise common.AccessUndeniedError(msg, common.AccessDeniedReason.ERROR)


def _get_group_policies(
    iam_client: IAMClient, group_arn: str, group_name: str
) -> List[common.Policy]:
    group_policies = []
    for inline_policy_name in iam_client.list_group_policies(GroupName=group_name)[
        "PolicyNames"
    ]:
        group_policies.append(
            _create_policy_from_inline_policy_response(
                inline_policy_response=iam_client.get_group_policy(
                    GroupName=group_name, PolicyName=inline_policy_name
                ),
                attachment_target_arn=group_arn,
                attachment_target_type="IAMGroup",
            )
        )
    for managed_policy_response in iam_client.list_attached_group_policies(
        GroupName=group_name
    )["AttachedPolicies"]:
        group_policies.append(
            _create_policy_from_managed_policy_response(
                iam_client,
                managed_policy_response,
                group_arn,
                "IAMGroup",
            )
        )
    return group_policies


@cachetools.cached(
    cache=cachetools.LRUCache(maxsize=512),
    key=lambda iam_client, policy_arn: keys.hashkey(policy_arn),
)
def _get_policy_document_default_version_from_policy_arn(
    iam_client: IAMClient, policy_arn: str
) -> str:
    default_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"][
        "DefaultVersionId"
    ]
    policy_document = iam_client.get_policy_version(
        PolicyArn=policy_arn, VersionId=default_version
    )["PolicyVersion"]["Document"]
    return json.dumps(policy_document)


@cachetools.cached(
    cache=cachetools.LRUCache(maxsize=512),
    key=lambda iam_client, principal: keys.hashkey(principal.arn),
)
def _get_principal_inline_policies(
    iam_client: IAMClient, principal: common.Principal
) -> Iterable[common.Policy]:
    role_policies = []
    for inline_policy_name in iam_client.list_role_policies(RoleName=principal.name)[
        "PolicyNames"
    ]:
        role_policies.append(
            _create_policy_from_inline_policy_response(
                inline_policy_response=iam_client.get_role_policy(
                    RoleName=principal.name, PolicyName=inline_policy_name
                ),
                attachment_target_arn=principal.arn,
                attachment_target_type="AssumedRole",
            )
        )
    return role_policies


def _get_role_policies(
    iam_client: IAMClient, principal: common.Principal
) -> List[common.Policy]:
    role_policies = _get_principal_inline_policies(iam_client, principal)
    for managed_policy_response in iam_client.list_attached_role_policies(
        RoleName=principal.name
    )["AttachedPolicies"]:
        role_policies.append(
            _create_policy_from_managed_policy_response(
                iam_client=iam_client,
                managed_policy_response=managed_policy_response,
                attachment_target_arn=principal.name,
                attachment_target_type="AssumedRole",
            )
        )
    return role_policies


def _get_user_policies(
    iam_client: IAMClient, principal: common.Principal
) -> List[common.Policy]:
    user_policies = []
    for inline_policy_name in iam_client.list_user_policies(UserName=principal.name)[
        "PolicyNames"
    ]:
        user_policies.append(
            _create_policy_from_inline_policy_response(
                inline_policy_response=(
                    iam_client.get_user_policy(
                        UserName=principal.name, PolicyName=inline_policy_name
                    )
                ),
                attachment_target_arn=principal.arn,
                attachment_target_type="IAMUser",
            )
        )
    for managed_policy_response in iam_client.list_attached_user_policies(
        UserName=principal.name
    )["AttachedPolicies"]:
        user_policies.append(
            _create_policy_from_managed_policy_response(
                iam_client,
                managed_policy_response,
                principal.name,
                "IAMUser",
            )
        )
    return user_policies


def get_iam_client_in_account(
    config: common.Config,
    account_id: str,
) -> IAMClient:
    if config.account_id == account_id:
        return config.iam_client

    return _get_cross_account_iam_client(
        target_account=account_id,
        session=config.session,
        cross_account_role_name=config.cross_account_role_name,
    )


def get_iam_identity_policies_for_principal(
    iam_client: IAMClient, principal: common.Principal
) -> List[common.Policy]:
    logger.debug(f"Gathering identity policies for [principal_arn: {principal.arn}]")
    policies = []
    if principal.type == "AssumedRole":
        policies.extend(_get_role_policies(iam_client, principal))
    elif principal.type == "IAMUser":
        policies.extend(_get_user_policies(iam_client, principal))
        for group in iam_client.list_groups_for_user(UserName=(principal.name))["Groups"]:
            policies.extend(
                _get_group_policies(iam_client, group["Arn"], group["GroupName"])
            )
    return policies


def get_permissions_boundary_for_principal(
    iam_client: IAMClient, principal: common.Principal
) -> Optional[common.Policy]:
    principal_response = {}
    if principal.type == "IAMUser":
        principal_response = iam_client.get_user(UserName=(principal.name))["User"]
    elif principal.type == "AssumedRole":
        principal_response = iam_client.get_role(RoleName=(principal.name))["Role"]

    if principal_response.get("PermissionsBoundary"):
        return _create_policy_from_permissions_boundary_response(
            iam_client,
            iam_client.get_user(UserName=(principal.name))["User"]["PermissionsBoundary"],
            principal.arn,
            principal.type,
        )


def replace_principal_in_policy(
    original_principal: str, replacement_principal: str, policy: str
) -> str:
    policy_dict = json.loads(policy)
    for statement in policy_dict.get("Statement", []):
        principal_key = "Principal" if "Principal" in statement else "NotPrincipal"
        principal_value = statement.get(principal_key, {})
        if principal_value == original_principal:
            statement[principal_key] = replacement_principal
        elif isinstance(principal_value, collections.abc.Mapping) and principal_value.get("AWS") == original_principal:
            statement[principal_key]["AWS"] = replacement_principal
    return json.dumps(policy_dict)
