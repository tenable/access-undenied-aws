from typing import Set, Optional, Sequence

from aws_cdk import (
    Duration,
    Stack,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_logs as logs,
    aws_events as events,
    aws_events_targets as targets,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    Aws,
)
from constructs import Construct

email_address_to_notify = "me@example.com"


class LambdaCdkStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        layer = lambda_.LayerVersion(
            self,
            "AccessUndeniedLayer",
            code=lambda_.Code.from_asset("layer"),
            description="Access Undenied Layer",
            compatible_runtimes=[
                lambda_.Runtime.PYTHON_3_8,
                lambda_.Runtime.PYTHON_3_9,
            ],
            compatible_architectures=[
                lambda_.Architecture.ARM_64,
                lambda_.Architecture.X86_64,
            ],
        )

        notify_topic = sns.Topic(
            self, "NotificationsTopic", display_name="Access Undenied SNS notifications"
        )

        access_undenied_role_name = (
            self.node.try_get_context("AccessUndeniedRoleName") or "AccessUndeniedRole"
        )
        access_undenied_lambda_role_name = (
            self.node.try_get_context("AccessUndeniedLambdaRoleName")
            or "AccessUndeniedLambdaRole"
        )
        account_set = set(self.node.try_get_context("AccountList")) or {}
        account_set.update({Aws.ACCOUNT_ID})
        access_undenied_lambda = lambda_.Function(
            self,
            "AccessUndeniedLambda",
            function_name="AccessUndenied",
            description="Access Undenied",
            architecture=lambda_.Architecture.ARM_64,
            runtime=lambda_.Runtime.PYTHON_3_8,
            timeout=Duration.minutes(3),
            memory_size=256,
            log_retention=logs.RetentionDays.ONE_DAY,
            code=lambda_.Code.from_asset("./fns"),
            handler="lambda_handler.lambda_handler",
            layers=[layer],
            environment={"SNS_TOPIC_ARN": notify_topic.topic_arn},
            role=iam.Role(
                self,
                access_undenied_lambda_role_name,
                assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
                role_name=access_undenied_lambda_role_name,
                managed_policies=[
                    iam.ManagedPolicy.from_aws_managed_policy_name(
                        "service-role/AWSLambdaBasicExecutionRole"
                    )
                ],
                inline_policies={
                    "AccessUndeniedLambdaInlinePolicy": iam.PolicyDocument(
                        statements=[
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "sts:AssumeRole",
                                ],
                                resources=_get_access_undenied_role_arns(
                                    account_set, access_undenied_role_name
                                ),
                            ),
                            iam.PolicyStatement(
                                effect=iam.Effect.ALLOW,
                                actions=[
                                    "ecr:GetRepositoryPolicy",
                                    "iam:Get*",
                                    "iam:List*",
                                    "iam:SimulateCustomPolicy",
                                    "kms:GetKeyPolicy",
                                    "lambda:GetPolicy",
                                    "organizations:List*",
                                    "organizations:Describe*",
                                    "s3:GetBucketPolicy",
                                    "secretsmanager:GetResourcePolicy",
                                    "sts:DecodeAuthorizationMessage",
                                ],
                                resources=[
                                    "*",
                                ],
                            ),
                        ],
                    ),
                },
            ),
        )

        notify_topic.add_subscription(
            sns_subscriptions.EmailSubscription(email_address_to_notify)
        )
        notify_topic.grant_publish(access_undenied_lambda)

        rule = events.Rule(
            self,
            "accessUndeniedInvocationRule",
            event_pattern=events.EventPattern(detail={"errorCode": ["AccessDenied"]}),
        )
        rule.add_target(
            targets.LambdaFunction(access_undenied_lambda, retry_attempts=2)
        )


def _get_access_undenied_role_arns(
    account_set: Set[str], access_undenied_role_name: str
) -> Optional[Sequence[str]]:
    return [
        f"arn:aws:iam::{account_id}:role/{access_undenied_role_name}"
        for account_id in account_set
    ]
