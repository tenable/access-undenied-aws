import json
from typing import Optional, TYPE_CHECKING, Sequence, Dict, Any

from access_undenied_aws import (
    results,
    logger,
)
from access_undenied_aws import event
from access_undenied_aws import common
from access_undenied_aws import event_permission_data
from access_undenied_aws import iam_policy_data
from access_undenied_aws import result_details

if TYPE_CHECKING:
    from mypy_boto3_iam.type_defs import (
        EvaluationResultTypeDef,
        SimulateCustomPolicyRequestRequestTypeDef,
        StatementTypeDef,
    )
else:
    EvaluationResultTypeDef = object
    SimulateCustomPolicyRequestRequestTypeDef = object
    StatementTypeDef = object

POLICY_TYPE_TO_EXPLICIT_DENY_ASSESSMENT_RESULT_MAPPING = {
    common.PolicyType.IDENTITY_MANAGED_POLICY: common.AccessDeniedReason.IDENTITY_POLICY_EXPLICIT_DENY,
    common.PolicyType.IDENTITY_INLINE_POLICY: common.AccessDeniedReason.IDENTITY_POLICY_EXPLICIT_DENY,
    common.PolicyType.RESOURCE_POLICY: common.AccessDeniedReason.RESOURCE_POLICY_EXPLICIT_DENY,
    common.PolicyType.SERVICE_CONTROL_POLICY: common.AccessDeniedReason.SCP_EXPLICIT_DENY,
    common.PolicyType.PERMISSIONS_BOUNDARY_POLICY: common.AccessDeniedReason.PERMISSIONS_BOUNDARY_EXPLICIT_DENY,
    common.PolicyType.COMBINED_SERVICE_CONTROL_POLICY: common.AccessDeniedReason.SCP_EXPLICIT_DENY,
}


class SimulateCustomPolicyResultAnalyzer(object):
    def __init__(
        self,
        simulate_custom_policy_request: SimulateCustomPolicyRequestRequestTypeDef,
        simulate_custom_policy_response: EvaluationResultTypeDef,
        event_: event.Event,
        event_permission_data_: event_permission_data.EventPermissionData,
        iam_policy_data_: iam_policy_data.IamPolicyData,
        guardrail_policy: Optional[common.Policy],
    ) -> None:
        self.simulate_custom_policy_request = simulate_custom_policy_request
        self.simulate_custom_policy_response = simulate_custom_policy_response
        self.event = event_
        self.event_permission_data = event_permission_data_
        self.iam_policy_data_ = iam_policy_data_
        self.guardrail_policy = guardrail_policy

    def analyze(
        self,
    ) -> results.AnalysisResult:
        matched_explicit_deny_policy = _get_matched_explicit_deny_policy(
            simulate_custom_policy_request=self.simulate_custom_policy_request,
            simulate_custom_policy_response=self.simulate_custom_policy_response,
            event_permission_data_=self.event_permission_data,
            iam_policy_data_=self.iam_policy_data_,
            guardrail_policy=self.guardrail_policy,
        )
        if not matched_explicit_deny_policy:
            missing_allow_reason = self._identify_missing_allow_reason()
            return results.AnalysisResult(
                event_id=self.event.event_id,
                assessment_result=missing_allow_reason,
                result_details_=self._create_new_result_details(missing_allow_reason),
            )

        if (
            matched_explicit_deny_policy.policy_type
            is common.PolicyType.COMBINED_SERVICE_CONTROL_POLICY
        ):
            matched_explicit_deny_policy = _get_matched_scp_from_combined_scp(
                matched_explicit_deny_policy
            )

        return results.AnalysisResult(
            event_id=self.event.event_id,
            assessment_result=POLICY_TYPE_TO_EXPLICIT_DENY_ASSESSMENT_RESULT_MAPPING[
                matched_explicit_deny_policy.policy_type
            ],
            result_details_=result_details.ExplicitDenyResultDetails(
                policy_arn=matched_explicit_deny_policy.policy_arn,
                policy_name=matched_explicit_deny_policy.policy_name,
                explicit_deny_policy_statement=matched_explicit_deny_policy.matched_statement,
                attachment_target_arn=matched_explicit_deny_policy.attachment_target_arn,
            ),
        )

    def _create_new_result_details(
        self, missing_allow_reason: common.AccessDeniedReason
    ) -> result_details.ResultDetails:
        target_principal_arn = (
            self.guardrail_policy.attachment_target_arn
            if missing_allow_reason
            in [
                common.AccessDeniedReason.SCP_MISSING_ALLOW,
                common.AccessDeniedReason.PERMISSIONS_BOUNDARY_MISSING_ALLOW,
            ]
            else self.event_permission_data.principal.arn
        )
        return result_details.MissingAllowResultDetails(
            simulate_custom_policy_response=self.simulate_custom_policy_response,
            missing_allow_reason=missing_allow_reason,
            target_principal_arn=target_principal_arn,
            target_resource_arn=self.event_permission_data.resource.arn,
        )

    def _identify_missing_allow_reason(self) -> common.AccessDeniedReason:
        if self.simulate_custom_policy_response["EvalDecision"] == "allowed":
            return common.AccessDeniedReason.ALLOWED

        # EvalDecisionDetails only appears in cross-account-cases (or IAM Role/KMS Key)
        cross_account_evaluation_decision_details = (
            self.simulate_custom_policy_response.get("EvalDecisionDetails", {})
        )
        resource_policy_cross_account_implicit_deny = (
            cross_account_evaluation_decision_details.get("Resource Policy")
            == "implicitDeny"
        )
        identity_policy_cross_account_implicit_deny = (
            cross_account_evaluation_decision_details.get("IAM Policy") == "implicitDeny"
        )
        if identity_policy_cross_account_implicit_deny:
            if resource_policy_cross_account_implicit_deny:
                return common.AccessDeniedReason.CROSS_ACCOUNT_MISSING_ALLOW
            return common.AccessDeniedReason.IDENTITY_POLICY_MISSING_ALLOW

        if resource_policy_cross_account_implicit_deny:
            return common.AccessDeniedReason.RESOURCE_POLICY_MISSING_ALLOW

        if (
            cross_account_evaluation_decision_details.get("Permissions Boundary Policy")
            == "implicitDeny"
        ):
            if self.guardrail_policy.policy_type == "Permissions Boundary Policy":
                return common.AccessDeniedReason.PERMISSIONS_BOUNDARY_MISSING_ALLOW
            return common.AccessDeniedReason.SCP_MISSING_ALLOW

        # same-account case
        if (
            self.simulate_custom_policy_response.get(
                "PermissionsBoundaryDecisionDetail", {}
            ).get("PermissionsBoundaryDecisionDetail")
            is False
        ):
            return (
                common.AccessDeniedReason.PERMISSIONS_BOUNDARY_MISSING_ALLOW
                if self.guardrail_policy.policy_type
                is common.PolicyType.PERMISSIONS_BOUNDARY_POLICY
                else common.AccessDeniedReason.SCP_MISSING_ALLOW
            )

        return common.AccessDeniedReason.IDENTITY_POLICY_MISSING_ALLOW


def _extract_matching_statement(
    matched_statement_response: StatementTypeDef, policy_lines: Sequence[str]
) -> Optional[Dict[str, Any]]:
    line_start_index = matched_statement_response["StartPosition"]["Line"] - 1
    line_end_index = matched_statement_response["EndPosition"]["Line"] - 1
    if line_start_index != line_end_index:
        # Every single SimulateCustomPolicy response we have seen has returned
        # a single-line match and ignored line breaks in the original policy
        raise common.AccessUndeniedError(
            "SimulateCustomPolicy returned multiline statement match,"
            "currently unsupported.",
            common.AccessDeniedReason.ERROR,
        )

    col_start_index = matched_statement_response["StartPosition"]["Column"] - 1
    col_end_index = matched_statement_response["EndPosition"]["Column"] - 1
    try:
        return json.loads(
            policy_lines[line_start_index][col_start_index:col_end_index].lstrip(", ")
        )

    except json.JSONDecodeError:
        error_message = (
            "Could not decode matching statement"
            f" [matched_statement_response:{matched_statement_response}],"
            f" [policy_document:{str(policy_lines)}]"
        )
        logger.error(error_message)
        raise common.AccessUndeniedError(
            error_message,
            common.AccessDeniedReason.ERROR,
        )


def _get_matched_explicit_deny_policy(
    simulate_custom_policy_request: SimulateCustomPolicyRequestRequestTypeDef,
    simulate_custom_policy_response: EvaluationResultTypeDef,
    event_permission_data_: event_permission_data.EventPermissionData,
    iam_policy_data_: iam_policy_data.IamPolicyData,
    guardrail_policy: common.Policy,
) -> Optional[common.MatchedPolicy]:
    if not simulate_custom_policy_response.get(
        "MatchedStatements"
    ) and not simulate_custom_policy_response.get("ResourceSpecificResults", [{}])[0].get(
        "MatchedStatements"
    ):
        return None

    for matched_statement in simulate_custom_policy_response.get(
        "ResourceSpecificResults", [{}]
    )[0].get("MatchedStatements") or simulate_custom_policy_response.get(
        "MatchedStatements"
    ):
        policy = None
        policy_document_lines = []
        policy_type = matched_statement["SourcePolicyType"]
        if policy_type == "IAM Policy":
            policy_ind = int(matched_statement["SourcePolicyId"].split(".")[-1]) - 1
            policy = iam_policy_data_.identity_policies[policy_ind]
            policy_document_lines = simulate_custom_policy_request["PolicyInputList"][
                policy_ind
            ].splitlines()
        if policy_type == "Permissions Boundary Policy":
            policy = guardrail_policy
            policy_document_lines = simulate_custom_policy_request[
                "PermissionsBoundaryPolicyInputList"
            ][0].splitlines()
        if policy_type == "Resource Policy":
            policy = iam_policy_data_.resource_policy
            policy_document_lines = simulate_custom_policy_request[
                "ResourcePolicy"
            ].splitlines()

        matched_statement = _extract_matching_statement(
            matched_statement, policy_document_lines
        )
        if matched_statement.get("Effect") != "Deny":
            continue

        if policy_type == "Resource Policy":
            if (
                iam_policy_data_.caller_arn_placeholder
                != event_permission_data_.principal.arn
            ):
                # Replace caller arn placeholder with original caller arn
                matched_statement = json.loads(
                    json.dumps(matched_statement).replace(
                        iam_policy_data_.caller_arn_placeholder,
                        iam_policy_data_.caller_arn,
                    )
                )
        return common.MatchedPolicy(json.dumps(matched_statement), policy)
    return None


def _get_matched_scp_from_combined_scp(
    matched_policy: common.MatchedPolicy,
) -> common.MatchedPolicy:
    statement = json.loads(matched_policy.matched_statement)
    if "Sid" not in statement or len(statement["Sid"].split("/")) != 4:
        raise common.AccessUndeniedError(
            "Could not get matched SCP from combined SCP, "
            f"[matched_policy: {matched_policy}].",
            common.AccessDeniedReason.ERROR,
        )

    _, policy_id, policy_name, statement_sid = statement["Sid"].split("/")
    statement["Sid"] = statement_sid
    return common.MatchedPolicy(
        matched_statement=json.dumps(statement),
        policy=common.Policy(
            attachment_target_arn=matched_policy.attachment_target_arn,
            attachment_target_type=matched_policy.attachment_target_type,
            policy_name=policy_name,
            policy_arn=policy_id,
            policy_document=json.dumps(statement),
            policy_type=common.PolicyType.SERVICE_CONTROL_POLICY,
        ),
    )
