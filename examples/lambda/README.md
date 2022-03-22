# Setting up AccessUndenied on a Lambda function

## Creating an S3 Bucket with SCP Data
1. Create an S3 Bucket.
2. Locally run `access-undenied-aws --profile <management-account-profile> get-scps`. (If you're having trouble with
this, read the main readme file here: https://github.com/ermetic/access-undenied-aws.
3. Upload the created file `scp_data.json` to your bucket.
## Creating an IAM Role
Create an IAM Role called `AccessUndeniedLambdaRole` with the following permissions:
1. `SecurityAudit` managed policy or this custom policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccessUndeniedLeastPrivilegePolicy",
      "Effect": "Allow",
      "Action": [
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
        "sts:DecodeAuthorizationMessage"
      ],
      "Resource": "*"
    }
  ]
}
```

2. This custom policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AccessUndeniedAssumeRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::<management_account_id>:role/AccessUndeniedRole",
        "arn:aws:iam::<account_1_id>:role/AccessUndeniedRole",
        "arn:aws:iam::<account_2_id>:role/AccessUndeniedRole",
        "..."
      ]
    },
    {
      "Sid": "AccessUndeniedReadSCPData",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/scp_data.json"
    }
  ]
}
```
Replacing the bucket name `my-bucket` with the name of your bucket.
3. This role trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
## Publishing the Lambda Layer
Since `access-undenied-aws` is not automatically imported by Lambda, we must create a lambda layer that imports it.
Make a directory:
`mkdir access_undenied_lambda_layer`
Create the lambda layer zip file, more details: https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
```
python3.8 -m pip install --upgrade -t python/ access-undenied-aws
zip -r layer.zip python
```
Publish the lambda layer:
```
aws lambda publish-layer-version --layer-name access-undenied-layer --description "Access Undenied layer" \
--license-info "Apache-2.0" --zip-file fileb://layer.zip \d
--compatible-runtimes python3.8 python3.9 \
--compatible-architectures "arm64" "x86_64" 
```
## Creating the Lambda function
1. Zip the Lambda handler code
`zip lambda_handler.zip path-to-lambda-handler.py`
2. Create the function
```
aws lambda create-function \
--function-name access-undenied-lambda \
--runtime python3.8 \
--zip-file fileb://lamba_handler.zip \
--handler lambda_handler.lambda_handler \
--timeout 180 \
--memory-size 256 \
--role arn:aws:iam::123456789012:role/AccessUndeniedLambdaRole
--layers arn:aws:lambda:us-east-2:1234567890123:layer:access-undenied-layer:1
```

And... We're good to go! Invoke the function as you like, attach it to EventBridge, invoke it from the CLI or from any SDK.