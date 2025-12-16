# Amazon S3 Encryption Client for Go V4

[![Go Build status](https://github.com/aws/amazon-s3-encryption-client-go/actions/workflows/go-test.yml/badge.svg?branch=main)](https://github.com/aws/amazon-s3-encryption-client-go/actions/workflows/go-test.yml)  [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/aws/amazon-s3-encryption-client-go/blob/main/LICENSE)

This library provides an S3 client that supports client-side encryption.
`amazon-s3-encryption-client-go` is the v4 of the Amazon S3 Encryption Client for the Go programming language.

The v4 encryption client requires a minimum version of `Go 1.24`.

Check out the [release notes](https://github.com/aws/amazon-s3-encryption-client-go/blob/main/CHANGELOG.md) for information about the latest bug
fixes, updates, and features added to the encryption client.

Jump To:
* [Getting Started](#getting-started)
* [Migration](#migration)

## Maintenance and support for SDK major versions

For information about maintenance and support for SDK major versions and their underlying dependencies, see the
following in the AWS SDKs and Tools Shared Configuration and Credentials Reference Guide:

* [AWS SDKs and Tools Maintenance Policy](https://docs.aws.amazon.com/credref/latest/refdocs/maint-policy.html)
* [AWS SDKs and Tools Version Support Matrix](https://docs.aws.amazon.com/credref/latest/refdocs/version-support-matrix.html)

### Go version support policy

The v4 Encryption Client follows the upstream [release policy](https://go.dev/doc/devel/release#policy)
with an additional six months of support for the most recently deprecated
language version.

**AWS reserves the right to drop support for unsupported Go versions earlier to
address critical security issues.**

## Getting started
To get started working with the S3 Encryption Client set up your project for Go modules, and retrieve the client's dependencies with `go get`.
This example shows how you can use the v4 encryption client to make a `PutItem` request using a KmsKeyring.

###### Initialize Project
```sh
$ mkdir ~/encryptionclient
$ cd ~/encryptionclient
$ go mod init encryptionclient
```
###### Add SDK Dependencies
```sh
$ go get github.com/aws/amazon-s3-encryption-client-go/v4
```

###### Write Code
In your preferred editor add the following content to `main.go`

```go
package main

import (
	"context"
	"log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	
	// Import the materials and client package 
	"github.com/aws/amazon-s3-encryption-client-go/v4/client"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
)

func main() {
	ctx := context.Background()
    // Using the SDK's default configuration, loading additional config
    // and credentials values from the environment variables, shared
    // credentials, and shared configuration files
    cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
    if err != nil {
        log.Fatalf("unable to load SDK config, %v", err)
    }
	key := "testObjectWithNewEncryptionClient"
	plaintext := "This is a test.\n"
	
	s3Client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)

	// Create the keyring and CMM
	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, kmsKeyArn, func(options *materials.KeyringOptions) {
		options.EnableLegacyWrappingAlgorithms = false
	}))
	if err != nil {
		log.Fatalf("error while creating new CMM")
	}

	s3EncryptionClient, err := client.New(s3Client, cmm)
	
	_, err = s3EncryptionClient.PutObject(ctx, &s3Client.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte(plaintext)),
	})
	if err != nil {
		log.Fatalf("error calling putObject: %v", err)
	}
}
```

## Migration

This version of the library supports reading encrypted objects from previous versions with extra configuration.
It also supports writing objects with non-legacy algorithms.
The list of legacy modes and operations will be provided below.

* [3.x to 4.x Migration Guide](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v4-migration.html)
* [2.x to 3.x Migration Guide](https://docs.aws.amazon.com/amazon-s3-encryption-client/latest/developerguide/go-v3-migration.html)

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
