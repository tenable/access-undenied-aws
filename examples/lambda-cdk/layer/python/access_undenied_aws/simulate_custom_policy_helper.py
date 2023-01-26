import copy
import json
import re
from typing import (
    List,
    Sequence,
    Optional,
    TYPE_CHECKING,
    Dict,
    Any,
    Set,
    Iterable,
)

from access_undenied_aws import simulate_custom_policy_result_analyzer
from access_undenied_aws import (
    event_permission_data,
    iam_utils,
    event,
    iam_policy_data,
    common,
    results,
    utils,
    logger,
)
from access_undenied_aws.iam_policy_data import IamPolicyData

if TYPE_CHECKING:
    from mypy_boto3_iam import IAMClient
    from mypy_boto3_iam.type_defs import (
        ContextEntryTypeDef,
        SimulateCustomPolicyRequestRequestTypeDef,
    )
else:
    ContextEntryTypeDef = object
    IAMClient = object
    SimulateCustomPolicyRequestRequestTypeDef = object


def _add_resource_field(resource_policy, resource_arn) -> str:
    """
    Policy simulator requires resource policies to have the
    resource field explicitly stated. That is not the case for all resource
    policies (e.g. IAM Trust Policies)
    """
    resource_policy_dict = json.loads(resource_policy)
    for statement in resource_policy_dict.get("Statement", []):
        statement.pop("NotResource", None)
        statement["Resource"] = resource_arn
    return json.dumps(resource_policy_dict)


def _get_context_keys_for_custom_policy(
    policy_input_list: List[str],
) -> Set[str]:
    context_keys = set()
    for policy_document in policy_input_list:
        for statement in json.loads(policy_document).get("Statement", []):
            for _, condition_type_map in statement.get("Condition", {}).items():
                for context_key in condition_type_map.keys():
                    context_keys.add(context_key)
    return context_keys


def _simulate_custom_policy(
    iam_client: IAMClient,
    cloudtrail_event_: event.Event,
    event_permission_data_: event_permission_data.EventPermissionData,
    iam_policy_data_: iam_policy_data.IamPolicyData,
    guardrail_policy: Optional[common.Policy],
    simulate_custom_policy_arguments_template: SimulateCustomPolicyRequestRequestTypeDef,
) -> Optional[results.AnalysisResult]:
    if guardrail_policy:
        simulate_custom_policy_arguments = copy.copy(
            simulate_custom_policy_arguments_template
        )
        simulate_custom_policy_arguments["PermissionsBoundaryPolicyInputList"] = [
            guardrail_policy.policy_document
        ]
    else:
        simulate_custom_policy_arguments = simulate_custom_policy_arguments_template

    simulate_custom_policy_response = iam_client.simulate_custom_policy(
        **simulate_custom_policy_arguments
    )["EvaluationResults"][0]
    if simulate_custom_policy_response["EvalDecision"] in [
        "explicitDeny",
        "implicitDeny",
    ]:
        return simulate_custom_policy_result_analyzer.SimulateCustomPolicyResultAnalyzer(
            simulate_custom_policy_request=simulate_custom_policy_arguments,
            simulate_custom_policy_response=simulate_custom_policy_response,
            event_=cloudtrail_event_,
            event_permission_data_=event_permission_data_,
            iam_policy_data_=iam_policy_data_,
            guardrail_policy=guardrail_policy,
        ).analyze()
    return None


def generate_context_key_list_for_simulate_custom_policy(
    iam_policy_data_: IamPolicyData, iam_client: IAMClient
) -> Iterable[str]:
    policy_input_list = [
        identity_policy.policy_document
        for identity_policy in iam_policy_data_.identity_policies
    ] + [
        boundary_policy.policy_document
        for boundary_policy in iam_policy_data_.guardrail_policies
    ]
    if iam_policy_data_.resource_policy:
        policy_input_list.append(iam_policy_data_.resource_policy.policy_document)
    return _get_context_keys_for_custom_policy(policy_input_list)


def generate_simulate_custom_policy_request(
    iam_policy_data_: IamPolicyData,
    event_permission_data_: event_permission_data.EventPermissionData,
    context: Sequence[ContextEntryTypeDef],
) -> SimulateCustomPolicyRequestRequestTypeDef:
    simulate_custom_policy_request = {
        "PolicyInputList": [
            policy.policy_document for policy in iam_policy_data_.identity_policies
        ],
        "ActionNames": (event_permission_data_.iam_permission,),
        "ResourceOwner": get_resource_owner_parameter_from_account_arn(
            resource_arn=event_permission_data_.resource.arn,
            resource_account_id=event_permission_data_.resource.account_id,
            iam_permission=event_permission_data_.iam_permission,
        ),
        "CallerArn": iam_policy_data_.caller_arn_placeholder,
        "ResourceArns": (event_permission_data_.resource.arn,),
        "ContextEntries": context,
    }

    if iam_policy_data_.resource_policy:
        # We can only perform one principal replacement,
        # but the principal parameter in the resource policy can be
        # arn:aws:iam::account:role/role-name or it can be
        # arn:aws:sts::account:assumed-role/role-name/role-session-name
        # We need to find out which principal, if any,
        # is used in the resource policy. :(
        iam_policy_data_.caller_arn = (
            event_permission_data_.principal.session_name
            if event_permission_data_.principal.session_name
            in iam_policy_data_.resource_policy.policy_document
            else event_permission_data_.principal.arn
        )
        simulate_custom_policy_request[
            "ResourcePolicy"
        ] = iam_utils.replace_principal_in_policy(
            original_principal=iam_policy_data_.caller_arn,
            replacement_principal=iam_policy_data_.caller_arn_placeholder,
            policy=_add_resource_field(
                iam_policy_data_.resource_policy.policy_document,
                event_permission_data_.resource.arn,
            ),
        )
    return simulate_custom_policy_request


def get_resource_owner_parameter_from_account_arn(
    resource_arn: str,
    resource_account_id: str,
    iam_permission: str,
) -> str:
    arn_match = re.match(common.RESOURCE_ARN_PATTERN, resource_arn)
    if (
        utils.get_regex_match_group_or_none(arn_match, "resource_type") == "key"
        or "AssumeRole" in iam_permission
    ):
        logger.debug(
            "IAM Role trust policies and KMS Key Policies are"
            " anomalous and are evaluated like cross-account"
            " policies."
            " Listing placeholder account id 123456789012..."
        )
        return f"arn:aws:iam::123456789012:root"

    return f"arn:aws:iam::{resource_account_id}:root"


def simulate_custom_policies(
    iam_client: IAMClient,
    cloudtrail_event_: event.Event,
    event_permission_data_: event_permission_data.EventPermissionData,
    iam_policy_data_: iam_policy_data.IamPolicyData,
    simulate_custom_policy_arguments_base: SimulateCustomPolicyRequestRequestTypeDef,
) -> Optional[results.AnalysisResult]:
    for guardrail_policy in iam_policy_data_.guardrail_policies or [None]:
        deny_result = _simulate_custom_policy(
            iam_client,
            cloudtrail_event_,
            event_permission_data_,
            iam_policy_data_,
            guardrail_policy,
            simulate_custom_policy_arguments_base,
        )
        if deny_result:
            return deny_result
    raise common.AccessUndeniedError(
        message="AccessUndenied could not find a reason for AccessDenied.",
        access_denied_reason=common.AccessDeniedReason.ALLOWED,
    )
