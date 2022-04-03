#!/usr/bin/env python3
import aws_cdk as cdk
from lambda_cdk.lambda_cdk_stack import LambdaCdkStack
from lambda_cdk.update_logical_id_aspect import UpdateLogicalIdAspect

app = cdk.App()
LambdaCdkStack(app, "AccessUndeniedLambdaCdkStack")

cdk.Aspects.of(app).add(UpdateLogicalIdAspect())

app.synth()
