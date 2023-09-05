# CDK

The Amazon S3 Encryption Client Go uses the AWS CDK to manage its CI infrastructure.
To setup CI infrastructure in your own account, make sure to specify the following environment variables:

* CDK_DEPLOY_ACCOUNT
* CDK_DEPLOY_REGION

## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
* `cdk synth`       emits the synthesized CloudFormation template
