# Access Undenied

Access Undenied parses AWS AccessDenied CloudTrail events, explains the reasons for them, and offers actionable fixes.

[![Twitter](https://img.shields.io/twitter/url/https/twitter.com/noamdahan.svg?style=social&label=Follow%20the%20author)](https://twitter.com/noamdahan)

- [Access Undenied](#access-undenied)
  - [Overview](#overview)
    - [Common use cases](#common-use-cases)
  - [Simple Startup](#simple-startup)
  - [Installation](#installation)
    - [Installation from pip](#installation-from-pip)
    - [Installation from source code (development)](#installation-from-source-code-development)
  - [Usage](#usage)
    - [Getting events](#getting-events)
    - [Permissions](#permissions)
      - [Same account assets only, no SCPs](#same-account-assets-only-no-scps)
      - [Cross-account assets and SCPs](#cross-account-assets-and-scps)
    - [CLI Commands](#cli-commands)
      - [Analyze](#analyze)
        - [Example:](#example)
      - [Get SCPs](#get-scps)
  - [Output Format](#output-format)
    - [Output Fields](#output-fields)
      - [AccessDeniedReason:](#accessdeniedreason)
      - [ResultDetails](#resultdetails)
        - [PoliciesToAdd](#policiestoadd)
        - [ExplicitDenyPolicies](#explicitdenypolicies)
  - [Acknowledgements](#acknowledgements)
  - [Appendices](#appendices)
    - [Setting up a venv](#setting-up-a-venv)
    - [Getting Cloudtrail events from the AWS Console's event history](#getting-cloudtrail-events-from-the-aws-consoles-event-history)
    - [Example Cloudtrail event](#example-cloudtrail-event)
    - [Least privilege AccessUndenied policy](#least-privilege-accessundenied-policy)

## Overview

Access Undenied analyzes AWS CloudTrail AccessDenied events, scans the environment to identify and explain the reasons
for them, and offers actionable least-privilege remediation suggestions.

Note: Access Undenied is *not yet live* and cannot be installed at this point.
### Common use cases
Sometimes, the [new and more detailed AccessDenied messages
provided by AWS](https://aws.amazon.com/blogs/security/aws-introduces-changes-to-access-denied-errors-for-easier-permissions-troubleshooting/)
will be sufficient. However, that is not always the case.
1. Some AccessDenied messages do not provide details. Among the
services with (many or exclusively) undetailed messages are: S3, SSO, EFS, EKS, GuardDuty, Batch, SQS, and many more.
2. When the reason for AccessDenied is an explicit deny, it can be difficult to track down 
and evaluate every relevant policy.
3. Specifically when the reason is an explicit deny in a service control policy (SCP), one has to find and
every single policy in the organization that applies to the account.
4. When the problem is a missing `Allow` statement, AccessUndenied automatically offers a least-privilege
policy based on the CloudTrail event.
## Simple Startup

Install AccessUndenied
```
pip install aws-access-undenied
```
Analyze a CloudTrail event file.
```
aws-access-undenied analyze --file event_history.json
```

## Installation

### Installation from pip

```
python -m pip install aws-access-undenied 
```

### Installation from source code (development)

To install from source code, you can [set up a venv](#setting-up-a-venv) (optionally), and within that venv

```
python -m pip install --editable .
```

## Usage

### Getting events

Access Undenied works by analyzing a CloudTrail event where access was denied and the error code is either AccessDenied
or Client.UnauthorizedOperation, it works on an input of one or more CloudTrail events. You can get them from wherever
you get events, they can be found in the event history in the console, or by the LookupEvents API, or through whatever
system you use in order to filter and detect events: Athena, Splunk, others. You can either download the records file 
(the default format for multiple events) or just copy and paste a single event. For an example of how to do 
this: [Getting Cloudtrail events from the AWS Console's event history](#getting-cloudtrail-events-from-the-aws-consoles-event-history)

### Permissions

Access Undenied runs with the default permissions of the environment running the cli command, and accepts
the `--profile` flag for using a different profile from .aws/credentials. The role running access-undenied should have
at be granted these permissions:
1. Attach the `SecurityAudit` managed policy
2. Attach this inline policy: `AccessUndeniedAssumeRole`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccessUndenied-AssumeRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::<management_account_id>:role/AccessUndeniedRole",
        "arn:aws:iam::<account_1_id>:role/AccessUndeniedRole",
        "arn:aws:iam::<account_2_id>:role/AccessUndeniedRole",
        "..."
      ]
    }
  ]
}
```
If you do not wish to attach `SecurityAudit`, you may instead attach the updating [least-privilege
 AccessUndenied policy](#least-privilege-accessundenied-policy)
#### Same account assets only, no SCPs

When both the resource and the principal are in the same account as the credentials used to run AccessUndenied and
Service Control Policies (SCPs) do not need to be considered, it is sufficient to just run AccessUndenied with default
credentials or a profile, and you do not need to set up any additional profiles.

#### Cross-account assets and SCPs

To consider assets in multiple accounts and/or SCPs in the management account, we need to set up AWS cross-account roles
with the [same policy](#permissions) and the same name as each other (the default is `AccessUndeniedRole`)

when setting up these roles, remember to set up the appropriate trust policy (trusting the credentials in the source
account, the one you're running AccessUndenied in):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<source_account>:role/AccessUndeniedRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {}
    }
  ]
}
```
Create an identity policy (inline or managed) with the following permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "kms:GetKeyPolicy",
        "organizations:DescribeOrganization",
        "s3:GetBucketPolicy",
        "secretsmanager:GetResourcePolicy",
        "sts:DecodeAuthorizationMessage"
      ],
      "Resource": "*"
    }
  ]
}
```


### CLI Commands

Simplest command

```
aws-access-undenied analyze --events-file cloudtrail_events.json
```

All options:

```
Options:
  -v, --verbosity LVL  Either CRITICAL, ERROR, WARNING, INFO or DEBUG
  --profile TEXT       the AWS profile to use (default is default profile)
  --help               Show this message and exit.

Commands:
  analyze   Analyzes AWS CloudTrail events and explains the reasons for...
  get-scps  Writes the organization's SCPs and organizational tree to a file
```

#### Analyze
This command is used to analyze AccessDenied events. It can be used either with the
`management-account-role-arn` parameter to retrieve SCPs, or with the
`scp-file` parameter to use a policy data file created by the [get_scps](#get-scps)
command.
```
Options:
  --events-file FILENAME          input file of CloudTrail events  [required]
  --scp-file TEXT                 Service control policy data file generated
                                  by the get_scps command.
  --management-account-role-arn TEXT
                                  a cross-account role in the management
                                  account of the organization, which must be
                                  assumable by your credentials.
  --cross-account-role-name TEXT  The name of the cross-account role for
                                  AccessUndenied to assume. default:
                                  AccessUndeniedRole
  --output-file TEXT              output file for results (default: no output
                                  to file)
  --suppress-output / --no-suppress-output
                                  should output to stdout be suppressed
                                  (default: not suppressed)
  --help                          Show this message and exit.

```
**Example:**
```
aws-access-undenied analyze --events-file events_file.json
```
#### Get SCPs
This command is used to writes the organization's SCPs and organizational tree
to an organizational policy data file. This command should be run from the management
account.
```
Options:
  --output-file TEXT  output file for scp data (default: scp_data.json)
  --help              Show this message and exit.
```
**Example:**
```
aws-access-undenied get-scps
```
Then when running analyzing (from the same account or a different account)
```
aws-access-undenied analyze --events-file events_file.json --scp-file scp_data.json
```

## Output Format
```json
{
  "EventId": "55555555-12ad-4f70-9140-d44428038119",
  "AssessmentResult": "Missing allow in an identity-based policy",
  "ResultDetails": {
    "PoliciesToAdd": [
      {
        "AttachmentTargetArn": "arn:aws:iam::123456789012:role/MyRole",
        "Policy": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": "rds:DescribeDBInstances",
              "Resource": "arn:aws:rds:ap-northeast-3:120252999260:db:*"
            }
          ]
        }
      }
    ]
  }
}
```
This output for example, tells us that access was denied because of there is no 
`Allow` statement in an identity-based policy.
To  remediate, we should attach to the IAM role 
`arn:aws:iam::123456789012:role/MyRole` the policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rds:DescribeDBInstances",
      "Resource": "arn:aws:rds:ap-northeast-3:120252999260:db:*"
    }
  ]
}
```
### Output Fields
#### AccessDeniedReason:
The reason why access was denied. Possible Values

Missing allow in:
* Identity policy
* Resource policy (in cross-account access)
* Both (in cases of cross-account access)
* Permissions boundary
* Service control policy (with allow-list SCP strategy)

Explicit deny from:
* Identity policy
* Resource policy
* Permissions boundary
* Service control policy

Invalid action:
* a principal or action that cannot be simulated by access undenied.

"Allowed"
An `"Allowed"` result means that access undenied couldn't find the reason 
for AccessDenied, this could be for a variety of reasons:
* Policies, resources and/or identities have changed since the CloudTrail event and access 
now actually allowed
* Unsupported resource policy type
* Unsupported policy type (VPC endpoint policy, session policy, etc.)
* Unsupported condition key
#### ResultDetails
These are the details of the result, explaining the remediation steps, 
this section may contain either `PoliciesToAdd` or `ExplicitDenyPolicies`.
##### PoliciesToAdd
These are the policies which need to be added to enable least-privilege access.
Each policy contains: 
* `AttachmentTargetArn`: the entity to which the new policy
should be attached
* `Policy`: The content of the policy to be added
##### ExplicitDenyPolicies
These are the policies cause explicit deny, which need to be removed or
modified to facilitate access. AccessUndenied also gives the specific
statement causing the `Deny` outcome.
* `AttachmentTargetArn`: the entity to which the policy causing explicit
deny is currently attached
* `PolicyArn`: The arn (if applicable) of the policy causing explicit deny.
For the sake of convenience, resource policies are represented by generic 
placeholder arns such as: `arn:aws:s3:::my-bucket/S3BucketPolicy`
* `PolicyName`: The policy name, if applicable. Resource policies
are represented by generic placeholder names such as `S3BucketPolicy`
* `PolicyStatement`: The specific statement in the aforementioned policy
causing explicit deny
## Acknowledgements
This project makes use of Ian Mckay's [iam-dataset](https://github.com/iann0036/iam-dataset) Ben
Kehoe's [aws-error-utils](https://github.com/benkehoe/aws-error-utils).
## Appendices
### Setting up a venv
```
python -m venv .venv
```

| Platform   |      Shell      | Command to activate virtual environment |
|------------|-----------------|-----------------------------------------|
| POSIX      | bash/zsh        | $ source .venv/bin/activate            |
|            | fish            | $ source .venv/bin/activate.fish       |
|            | csh/tcsh        | $ source .venv/bin/activate.csh        |
|            | PowerShell Core | $ .venv/bin/Activate.ps1               |
| Windows    | cmd.exe         | C:\> .venv\Scripts\activate.bat        |
|            | PowerShell      | PS C:\> .venv\Scripts\Activate.ps1     |

### Getting Cloudtrail events from the AWS Console's event history

1. Open the AWS console
2. Go to "CloudTrail"
3. In the sidebar on the left, click Event History
4. Find the event you're interested in checking. Unfortunately, the console doesn't let you filter by ErrorCode, so
   you'll have to filter some other way, e.g. by username or event name.
5. Download the event:
    1. By clicking the event, copying the event record, and pasting it to a json file locally. or,
    2. By clicking download events -> download as JSON in the top-right corner. (Access Undenied will handle all events
       where the ErrorCode is AccessDenied or Client.UnauthorizedOperation)

With the event saved locally, you may use the [cli command](#cli-arguments)

### Example Cloudtrail event

One event in file:

```json
{
  "awsRegion": "us-east-2",
  "eventID": "5ac7912b-fd5d-436a-b60c-8a4ec1f61cdc",
  "eventName": "ListFunctions20150331",
  "eventSource": "lambda.amazonaws.com",
  "eventTime": "2021-09-09T14:01:22Z",
  "eventType": "AwsApiCall",
  "userIdentity": {
    "accessKeyId": "ASIARXXXXXXXXXXXXXXXX",
    "accountId": "123456789012",
    "arn": "arn:aws:sts::123456789012:assumed-role/RscScpDisallow/1631196079303620000",
    "principalId": "AROARXXXXXXXXXXXXXXXX:1631196079303620000",
    "sessionContext": {
      "attributes": {
        "creationDate": "2021-09-09T14:01:20Z",
        "mfaAuthenticated": "false"
      },
      "sessionIssuer": {
        "accountId": "123456789012",
        "arn": "arn:aws:iam::123456789012:role/RscScpDisallow",
        "principalId": "AROARXXXXXXXXXXXXXXXX",
        "type": "Role",
        "userName": "RscScpDisallow"
      },
      "webIdFederationData": {}
    },
    "type": "AssumedRole"
  },
  "errorCode": "AccessDenied",
  "errorMessage": "User: arn:aws:sts::123456789012:assumed-role/RscScpDisallow/1631196079303620000 is not authorized to perform: lambda:ListFunctions on resource: * with an explicit deny",
  "sourceIPAddress": "xxx.xxx.xxx.xxx",
  "readOnly": true,
  "eventVersion": "1.08",
  "userAgent": "aws-cli/2.2.16 Python/3.8.8 Linux/4.19.128-microsoft-standard exe/x86_64.ubuntu.20 prompt/off command/lambda.list-functions",
  "requestID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxx",
  "managementEvent": true,
  "recipientAccountId": "123456789012",
  "eventCategory": "Management"
}
```

Multiple events in file:

```json
{
  "Records": [
    {
      "awsRegion": "us-east-1",
      "eventID": "xxxxxxxx-xxxx-xxxx-xxxx-8234c1555c12"
      //... rest of cloudtrail_event ...
    },
    {
      //... another cloudtrail_event ...
    }
    // more events...
  ]
}
```

### Least privilege AccessUndenied policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccessUndeniedLeastPrivilegePolicy",
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:SimulateCustomPolicy",
        "kms:GetKeyPolicy",
        "organizations:DescribeOrganization",
        "s3:GetBucketPolicy",
        "secretsmanager:GetResourcePolicy",
        "sts:DecodeAuthorizationMessage"
      ],
      "Resource": "*"
    }
  ]
}
```
