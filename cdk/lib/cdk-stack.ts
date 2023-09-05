import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
  Alias,
  Key
} from "aws-cdk-lib/aws-kms";
import {
  Effect,
  Role,
  PolicyDocument,
  PolicyStatement,
  FederatedPrincipal,
  ManagedPolicy,
} from "aws-cdk-lib/aws-iam";
import { 
  BlockPublicAccess,
  BlockPublicAccessOptions,
  Bucket,
  LifecycleRule
} from 'aws-cdk-lib/aws-s3';

export class S3ECGoGithub extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    
    // KMS Key - default policy is fine,
    // we use IAM to manage key permissions
    const S3ECGithubKMSKey = new Key(
      this,
      "S3ECGithubKMSKey",
      {
        enableKeyRotation: true,
        description: "KMS Key for GitHub Action Workflow",
      }
    )

    // KMS alias
    const S3ECGithubKMSKeyAlias = new Alias(
      this,
      "S3ECGithubKMSKeyAlias",
      {
        aliasName: "alias/S3EC-Go-Github-KMS-Key",
        targetKey: S3ECGithubKMSKey
      }
    )

    // S3 bucket
    const AccessConfiguration: BlockPublicAccessOptions = {
      blockPublicAcls: false,
      blockPublicPolicy: false,
      ignorePublicAcls: false,
      restrictPublicBuckets: false
    }
    const BucketLifecycleRule: LifecycleRule = {
        expiration: cdk.Duration.days(14),
        id: "Expire after 14 days"
    };
    const S3ECGithubTestS3Bucket = new Bucket(
      this,
      "S3ECGithubTestS3Bucket",
      {
        bucketName: "s3ec-go-github-test-bucket",
        lifecycleRules: [BucketLifecycleRule],
        blockPublicAccess: new BlockPublicAccess(AccessConfiguration)
      }
    )

    // S3 bucket policy
    const S3ECGithubS3BucketPolicy = new ManagedPolicy(
      this,
      "S3EC-Go-Github-S3-Bucket-Policy",
      {
        document: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
              ],
              resources: [
                S3ECGithubTestS3Bucket.bucketArn
              ],
            }),
          ]
        }),
      }
    );

    // KMS key policy
    const S3ECGithubKMSKeyPolicy = new ManagedPolicy(
      this,
      "S3EC-Go-Github-KMS-Key-Policy",
      {
        document: new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: [
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:GenerateDataKeyPair"
              ],
              resources: [
                S3ECGithubKMSKey.keyArn,
              ]
            })
          ]
        }),
      }
    )

    // IAM role 
    const GithubActionsPrincipal = new FederatedPrincipal(
      "arn:aws:iam::" + this.account + ":oidc-provider/token.actions.githubusercontent.com",
      {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:aws/amazon-s3-encryption-client-go:*"
        }
      },
      "sts:AssumeRoleWithWebIdentity"
    )
    const S3ECGithubTestRole = new Role(
      this,
      "s3-github-test-role",
      {
        assumedBy: GithubActionsPrincipal,
        roleName: "S3EC-Go-Github-test-role",
        description: " Grant GitHub S3 put and get and KMS encrypt, decrypt, and generate access for testing",
        path: "/",
        managedPolicies: [S3ECGithubS3BucketPolicy, S3ECGithubKMSKeyPolicy]
      }
    );
  }
}
