import aws_cdk as cdk
from constructs import Node
import jsii


@jsii.implements(cdk.IAspect)
class UpdateLogicalIdAspect:
    def visit(self, cdk_resource):
        cfn_resource = cdk_resource.node.default_child
        if cfn_resource:
            cfn_resource.override_logical_id(''.join(cdk_resource.node.path.split(Node.PATH_SEP)[1:]))
