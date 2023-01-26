from __future__ import annotations

import enum
from typing import Literal

RESOURCE_ARN_PATTERN = (
    r"^arn:(?P<partition>[^:\n]*):(?P<service>[^:\n]*):(?P<region>[^:\n]*):"
    r"(?P<account_id>[^:\n]*):(?P<ignore>(?P<resource_type>[^:\/\n]*)[:\/])?(?P<resource_id>.*)$"
)

AttachmentTargetType = Literal[
    "AWSAccount",
    "IAMGroup",
    "AssumedRole",
    "IAMUser",
    "Organizational Unit or Organization Root",
    "Resource: ECR Repository",
    "Resource: IAM Role",
    "Resource: KMS Key",
    "Resource: Lambda Function",
    "Resource: S3 Bucket",
    "Resource: SecretsManager Secret",
]


class AccessDeniedReason(str, enum.Enum):
    ALLOWED = "Allowed"
    CROSS_ACCOUNT_MISSING_ALLOW = (
        "Missing allows in an identity-based and "
        "a resource-based policy in cross-account access"
    )
    IDENTITY_POLICY_EXPLICIT_DENY = "Explicit deny in an identity-based policy"
    IDENTITY_POLICY_MISSING_ALLOW = "Missing allow in an identity-based policy"
    PERMISSIONS_BOUNDARY_EXPLICIT_DENY = "Explicit deny in a permissions boundary policy"
    PERMISSIONS_BOUNDARY_MISSING_ALLOW = "Missing allow in a permissions boundary policy"
    RESOURCE_POLICY_EXPLICIT_DENY = "Explicit deny in a resource-based policy"
    RESOURCE_POLICY_MISSING_ALLOW = (
        "Missing allow in a resource-based policy in cross-account access"
    )
    SCP_EXPLICIT_DENY = "Explicit deny in a service-control policy"
    SCP_MISSING_ALLOW = "Missing allow in a service-control policy"
    INVALID_ACTION = "Invalid action"
    ERROR = "Error"


class PolicyType(str, enum.Enum):
    IDENTITY_INLINE_POLICY = "Inline IAM Policy"
    IDENTITY_MANAGED_POLICY = "Managed IAM Policy"
    RESOURCE_POLICY = "Resource Policy"
    PERMISSIONS_BOUNDARY_POLICY = "Permissions Boundary Policy"
    SERVICE_CONTROL_POLICY = "Service Control Policy"
    COMBINED_SERVICE_CONTROL_POLICY = "Merged Composite Service Control Policy"


class AccessUndeniedError(Exception):
    def __init__(self, message: str, access_denied_reason: AccessDeniedReason):
        super(AccessUndeniedError, self).__init__(message)
        self.message = message
        self.access_denied_reason = access_denied_reason


class Config(object):
    def __init__(self) -> None:
        self.cross_account_role_name = None
        self.management_account_role_arn = None
        self.management_account_id = ""
        self.organization_nodes = dict()
        self.output_file = None
        self.output_json = {"Results": []}
        self.session = None
        self.suppress_output = False
        self.account_id = None
        self.iam_client = None


class Policy(object):
    def __init__(
        self,
        attachment_target_arn: str,
        attachment_target_type: AttachmentTargetType,
        policy_name: str,
        policy_arn: str,
        policy_document: str,
        policy_type: PolicyType,
    ) -> None:
        self.attachment_target_arn = attachment_target_arn
        self.attachment_target_type = attachment_target_type
        self.policy_name = policy_name
        self.policy_arn = policy_arn
        self.policy_document = policy_document
        self.policy_type = policy_type


class MatchedPolicy(Policy):
    def __init__(self, matched_statement: str, policy: Policy):
        super().__init__(
            policy.attachment_target_arn,
            policy.attachment_target_type,
            policy.policy_name,
            policy.policy_arn,
            policy.policy_document,
            policy.policy_type,
        )
        self.matched_statement = matched_statement


class Principal(object):
    def __init__(self) -> None:
        self.session_name = ""
        self.arn = ""
        self.type = ""
        self.account_id = ""
        self.name = ""


class Resource(object):
    def __init__(self, arn: str, account_id: str) -> None:
        self.arn = arn
        self.account_id = account_id
