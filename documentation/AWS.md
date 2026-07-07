# `PWN::AWS` — Cloud Security (90 service wrappers)

One thin module per AWS service, each wrapping the official `aws-sdk-*` gem
with the PWN `opts = {}` convention so they compose in the REPL and in
`pwn_eval`.

![AWS cloud security](diagrams/aws-cloud-security.svg)

## Credentials

Standard AWS SDK chain: `~/.aws/credentials` profile, env vars
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`), or
instance profile. Optionally pin in `~/.pwn/config.yml` under `aws:`.

## Quick enumeration

```ruby
PWN::AWS::STS.get_caller_identity
PWN::AWS::IAM.list_users
PWN::AWS::EC2.describe_instances(region: 'us-east-1')
PWN::AWS::S3.list_buckets
PWN::AWS::Lambda.list_functions
```

CLI: `pwn_aws_describe_resources -r us-east-1 -o out/`

## Service groups

| Group | Modules |
|---|---|
| Identity | `IAM` `STS` `CognitoIdentity` `CognitoIdentityProvider` `CognitoSync` `DirectoryService` |
| Compute | `EC2` `ECS` `ECR` `Lambda` `LambdaPreview` `Batch` `Lightsail` `ElasticBeanstalk` `AutoScaling` `ApplicationAutoScaling` `AppStream` |
| Storage | `S3` `Glacier` `EFS` `StorageGateway` `Snowball` |
| Data | `DynamoDB` `DynamoDBStreams` `RDS` `Redshift` `ElastiCache` `SimpleDB` `ElasticsearchService` |
| Network | `Route53` `Route53Domains` `ElasticLoadBalancing` `ElasticLoadBalancingV2` `APIGateway` `CloudFront` `DirectConnect` `WAF` `WAFRegional` `Shield` |
| Crypto | `KMS` `CloudHSM` `ACM` |
| Ops / Logs | `CloudTrail` `CloudWatch` `CloudWatchLogs` `CloudWatchEvents` `ConfigService` `SSM` `Health` `Inspector` `XRay` |
| Dev | `CodeBuild` `CodeCommit` `CodeDeploy` `CodePipeline` |
| Messaging | `SNS` `SQS` `SES` `Pinpoint` `Kinesis` `KinesisAnalytics` `Firehose` |
| ML / Media | `Rekognition` `Polly` `MachineLearning` `Lex` `ElasticTranscoder` |
| Infra | `CloudFormation` `CloudSearch` `CloudSearchDomain` `OpsWorks` `OpsWorksCM` `ServiceCatalog` `DataPipleline` `EMR` `SWF` `States` |
| IoT / Other | `IoT` `IoTDataPlane` `DeviceFarm` `GameLift` `Workspaces` `Support` `Budgets` `ImportExport` `SMS` `DatabaseMigrationService` `ApplicationDiscoveryService` `MarketplaceCommerceAnalytics` `MarketplaceMetering` |

## Offensive patterns

- **Enumerate** → `IAM` policies, `EC2` userdata, `Lambda` env vars, `S3`
  bucket ACLs, `SSM` parameters.
- **Misconfig** → public `S3`, wildcard `IAM` actions, unencrypted `RDS`,
  missing `CloudTrail`.
- **Escalate** → `iam:PassRole` + `lambda:Invoke`, `ssm:SendCommand`,
  `ec2:RunInstances` with instance profile.
- **Persist** → new access key, Lambda backdoor, EC2 userdata.

Record everything with `extro_observe(source: 'aws', …)` so
[Extrospection](Extrospection.md) can correlate later.

[← Home](Home.md)
