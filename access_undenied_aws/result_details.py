import json
from typing import Optional, TYPE_CHECKING, Dict, Any

from access_undenied_aws import common, logger

if TYPE_CHECKING:
    from mypy_boto3_iam.type_defs import (
        EvaluationResultTypeDef,
    )
else:
    EvaluationResultTypeDef = object


class ResultDetails(object):
    def __init__(self) -> None:
        self.policies = []

    def __str__(self) -> str:
        return "{}"


class MissingAllowResultDetails(ResultDetails):
    def __init__(
        self,
        simulate_custom_policy_response: EvaluationResultTypeDef,
        missing_allow_reason: common.AccessDeniedReason,
        target_principal_arn: Optional[str] = None,
        target_resource_arn: Optional[str] = None,
    ) -> None:
        super(MissingAllowResultDetails, self).__init__()
        if missing_allow_reason in [
            common.AccessDeniedReason.IDENTITY_POLICY_MISSING_ALLOW,
            common.AccessDeniedReason.CROSS_ACCOUNT_MISSING_ALLOW,
            common.AccessDeniedReason.SCP_MISSING_ALLOW,
            common.AccessDeniedReason.PERMISSIONS_BOUNDARY_MISSING_ALLOW,
        ]:
            identity_policy = {
                "AttachmentTargetArn": target_principal_arn,
                "Policy": _create_new_identity_policy(simulate_custom_policy_response),
            }
            self.policies.append(identity_policy)
        if missing_allow_reason in [
            common.AccessDeniedReason.RESOURCE_POLICY_MISSING_ALLOW,
            common.AccessDeniedReason.CROSS_ACCOUNT_MISSING_ALLOW,
        ]:
            resource_policy = {
                "AttachmentTargetArn": target_resource_arn,
                "Policy": _create_new_resource_policy(
                    simulate_custom_policy_response, target_principal_arn
                ),
            }
            self.policies.append(resource_policy)

    def __str__(self) -> str:
        output_s = super(MissingAllowResultDetails, self).__str__()
        output = json.loads(output_s)
        logger.debug(f"[output:{repr(output)}]")
        output["PoliciesToAdd"] = self.policies
        return json.dumps(output, indent=2)


class ExplicitDenyResultDetails(ResultDetails):
    def __init__(
        self,
        policy_arn: str,
        policy_name: str,
        explicit_deny_policy_statement: str,
        attachment_target_arn,
    ) -> None:
        super(ExplicitDenyResultDetails, self).__init__()
        self.policies = [
            {
                "PolicyArn": policy_arn,
                "PolicyName": policy_name,
                "AttachmentTargetArn": attachment_target_arn,
                "PolicyStatement": json.loads(explicit_deny_policy_statement),
            }
        ]

    def __str__(self) -> str:
        output_s = super(ExplicitDenyResultDetails, self).__str__()
        output = json.loads(output_s)
        output["ExplicitDenyPolicies"] = self.policies
        return json.dumps(output, indent=2)


def _create_new_identity_policy(
    simulate_custom_policy_response: EvaluationResultTypeDef,
) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": simulate_custom_policy_response["EvalActionName"],
                "Resource": simulate_custom_policy_response["EvalResourceName"],
            }
        ],
    }


def _create_new_resource_policy(
    simulate_custom_policy_response: EvaluationResultTypeDef, principal_arn: str
) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": principal_arn,
                },
                "Action": simulate_custom_policy_response["EvalActionName"],
                "Resource": simulate_custom_policy_response["EvalResourceName"],
            }
        ],
    }
