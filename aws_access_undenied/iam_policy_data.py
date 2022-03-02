from __future__ import annotations

from aws_access_undenied import common
from aws_access_undenied import event_permission_data
from aws_access_undenied import iam_utils
from aws_access_undenied import logger
from aws_access_undenied import resource_policy_utils
from aws_access_undenied import organization_node


class IamPolicyData(object):
    def __init__(self) -> None:
        self.identity_policies = []
        self.guardrail_policies = []
        self.resource_policy = None
        self.caller_arn = ""
        self.caller_arn_placeholder = ""

    @classmethod
    def from_event_permission_data(
        cls,
        config: common.Config,
        event_permission_data_: event_permission_data.EventPermissionData,
        region: str,
    ) -> IamPolicyData:
        iam_policy_data = cls()
        iam_client = iam_utils.get_iam_client_in_account(
            config, event_permission_data_.principal.account_id
        )
        iam_policy_data.identity_policies = (
            iam_utils.get_iam_identity_policies_for_principal(
                iam_client, event_permission_data_.principal
            )
        )
        permissions_boundary = iam_utils.get_permissions_boundary_for_principal(
            iam_client, event_permission_data_.principal
        )
        if permissions_boundary:
            iam_policy_data.guardrail_policies.append(permissions_boundary)

        if event_permission_data_.principal.account_id == config.management_account_id:
            logger.debug(
                "The identity"
                f" [principal.arn:{event_permission_data_.principal.arn}] is in"
                " the management account, so it is not affected by SCPs."
            )
        else:
            iam_policy_data.guardrail_policies.extend(
                organization_node.create_scp_policies_from_organization_node(
                    config.organization_nodes,
                    event_permission_data_.principal.account_id,
                )
            )
        iam_policy_data.resource_policy = resource_policy_utils.get_resource_policy(
            config, event_permission_data_, region
        )
        iam_policy_data.caller_arn_placeholder = (
            event_permission_data_.principal.arn
            if event_permission_data_.principal.type == "IAMUser"
            else f"arn:aws:iam::{event_permission_data_.principal.account_id}:user/ZXJtZXRpY1JzY1RlYW0="
        )
        return iam_policy_data
