from __future__ import annotations

import json
from typing import Optional, List, Dict, Any

from access_undenied_aws import common, logger


class OrganizationNode(object):
    def __init__(
        self,
        arn: str,
        id_: str,
        name: str,
        organization_node_type: common.AttachmentTargetType,
        parent: Optional[str],
        policies: List[Dict[str, Any]],
    ):
        self.arn = arn
        self.id = id_
        self.name = name
        self.organization_node_type = organization_node_type
        self.policies = policies
        self.parent = parent
        self.combined_policy = self._create_combined_scp_policy()

    def _create_combined_scp_policy(self) -> str:
        statement_list = []
        for policy in self.policies:
            for statement in json.loads(policy["PolicyDocument"])["Statement"]:
                statement["Sid"] = (
                    f"{self.id}/{policy['Id']}/{policy['Name']}/{statement['Sid']}"
                    if "Sid" in statement
                    else f"{self.id}/{policy['Id']}/"
                )
                statement_list.append(statement)
        return json.dumps({"Version": "2012-10-17", "Statement": statement_list})


def create_scp_policies_from_organization_node(
    organization_nodes: Dict[str, OrganizationNode],
    account_id: str,
) -> List[common.Policy]:
    scp_policies = []
    if account_id not in organization_nodes:
        logger.warning(
            f"Could not read SCPs for [account_id:{account_id}], continuing"
            " without SCPs"
        )
        return []
    current_organization_node = organization_nodes[account_id]
    while current_organization_node:
        if current_organization_node.combined_policy:
            policy = common.Policy(
                attachment_target_arn=current_organization_node.id,
                attachment_target_type=current_organization_node.organization_node_type,
                policy_name=current_organization_node.id,
                policy_arn=current_organization_node.id,
                policy_document=current_organization_node.combined_policy,
                policy_type=common.PolicyType.COMBINED_SERVICE_CONTROL_POLICY,
            )
            scp_policies.append(policy)
        current_organization_node = organization_nodes.get(
            current_organization_node.parent
        )
    return scp_policies
