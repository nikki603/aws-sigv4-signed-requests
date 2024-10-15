# AWSSigV4SignedWebRequests.ps1

This script signs REST requests with AWS Sig V4 as required by AWS Opensearch with Role Based Access Controls enabled. 
Powershell 7+ required.

## Configuration

Update the `-EndpointURI` parameter.

## Credentials

Update the $roleArn value in the script to test.

This script assumes you will be using an IAM role to authenticate to the Opensearch REST APIs. This IAM role should be already 
[mapped](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html#fgac-access-control) to Opensearch roles you require.
For testing locally you should be authenticated with valid credentials in any of the [default locations](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#configure-precedence). 
The IAM role you want to use should have an assume role policy allowing for your AWS credentials to assume the IAM role.
When running on EC2 instances, the IAM role you want to use should have a policy allowing for the EC2 instance role to assume the IAM role.

Example IAM assume role policy (Trust relationships)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAssumeRole",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::1234567890:role/My-Opensearch-Admins",
                    "arn:aws:iam::1234567890:role/cd-pipeline-agent-role"
                ]
            },
            "Action": [
                "sts:TagSession",
                "sts:AssumeRole"
            ]
        }
    ]
}
```

Example IAM permissions policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "es:ESHttpHead",
                "es:ESHttpGet",
                "es:ESHttpPut",
                "es:ESHttpPost",
                "es:esHttpDelete"
            ],
            "Effect": "Allow",
            "Resource": "arn:aws:es:us-east-1:1234567890:domain/my-opensearch/*",
            "Sid": "AllowIndexReadWrite"
        }
    ]
}
```


