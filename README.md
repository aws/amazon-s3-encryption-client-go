# Amazon S3 Encryption Client for Go V3

[![Go Build status](https://github.com/aws/amazon-s3-encryption-client-go/actions/workflows/go-test.yml/badge.svg?branch=main)](https://github.com/aws/amazon-s3-encryption-client-go/actions/workflows/go-test.yml)  [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/aws/amazon-s3-encryption-client-go/blob/main/LICENSE)

This library provides an S3 client that supports client-side encryption.
`amazon-s3-encryption-client-go` is the v3 of the Amazon S3 Encryption Client for the Go programming language.

The v3 encryption client requires a minimum version of `Go 1.20`.

Check out the [release notes](https://github.com/aws/amazon-s3-encryption-client-go/blob/main/CHANGELOG.md) for information about the latest bug
fixes, updates, and features added to the encryption client.

Jump To:
* [Getting Started](#getting-started)
* [Getting Help](#getting-help)
* [Contributing](#feedback-and-contributing)
* [More Resources](#resources)

## Maintenance and support for SDK major versions

For information about maintenance and support for SDK major versions and their underlying dependencies, see the
following in the AWS SDKs and Tools Shared Configuration and Credentials Reference Guide:

* [AWS SDKs and Tools Maintenance Policy](https://docs.aws.amazon.com/credref/latest/refdocs/maint-policy.html)
* [AWS SDKs and Tools Version Support Matrix](https://docs.aws.amazon.com/credref/latest/refdocs/version-support-matrix.html)

### Go version support policy

The v3 Encryption Client follows the upstream [release policy](https://go.dev/doc/devel/release#policy)
with an additional six months of support for the most recently deprecated
language version.

**AWS reserves the right to drop support for unsupported Go versions earlier to
address critical security issues.**

## Getting started
To get started working with the S3 Encryption Client set up your project for Go modules, and retrieve the client's dependencies with `go get`.
This example shows how you can use the v3 encryption client to make a `PutItem` request using a KmsKeyring.

###### Initialize Project
```sh
$ mkdir ~/encryptionclient
$ cd ~/encryptionclient
$ go mod init encryptionclient
```
###### Add SDK Dependencies
```sh
$ go get github.com/aws/amazon-s3-encryption-client-go
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
	"github.com/aws/amazon-s3-encryption-client-go/client"
	"github.com/aws/amazon-s3-encryption-client-go/materials"
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

	// Create the keyring and &CMM-long; (&CMM-short;)
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

This version of the library supports reading encrypted objects from previous versions.
It also supports writing objects with non-legacy algorithms.
The list of legacy modes and operations will be provided below.

### Examples
#### V2 KMS to V3

The following example demonstrates how to migrate a version v2 application that uses
the `NewKMSContextKeyGenerator` kms-key provider with a material
description and `AESGCMContentCipherBuilderV2` content cipher to
version v3 of the S3 Encryption Client for Go.

```go
func KmsContextV2toV3GCMExample() error {
 	bucket := LoadBucket()
 	kmsKeyAlias := LoadAwsKmsAlias()
 
 	objectKey := "my-object-key"
 	region := "us-west-2"
 	plaintext := "This is an example.\n"
 
 	// Create an S3EC Go v2 encryption client
 	// using the KMS client from AWS SDK for Go v1
	sessKms, err := sessionV1.NewSession(&awsV1.Config{
        Region: aws.String(region),
    })
 
 	kmsSvc := kmsV1.New(sessKms)
 	handler := s3cryptoV2.NewKMSContextKeyGenerator(kmsSvc, kmsKeyAlias, s3cryptoV2.MaterialDescription{})
 	builder := s3cryptoV2.AESGCMContentCipherBuilderV2(handler)
 	encClient, err := s3cryptoV2.NewEncryptionClientV2(sessKms, builder)
 	if err != nil {
 		log.Fatalf("error creating new v2 client: %v", err)
 	}
 
 	// Encrypt using KMS+Context and AES-GCM content cipher
 	_, err = encClient.PutObject(s3V1.PutObjectInput{
 		Bucket: aws.String(bucket),
 		Key:    aws.String(objectKey),
 		Body:   bytes.NewReader([]byte(plaintext)),
 	})
 	if err != nil {
 		log.Fatalf("error calling putObject: %v", err)
 	}
 	fmt.Printf("successfully uploaded file to %s/%s\n", bucket, key)
 
 	// Create an S3EC Go v3 client
 	// using the KMS client from AWS SDK for Go v2
 	ctx := context.Background()
 	cfg, err := config.LoadDefaultConfig(ctx,
 		config.WithRegion(region),
 	)
 
 	kmsV2 := kms.NewFromConfig(cfg)
 	cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsV2, kmsKeyAlias))
 	if err != nil {
 		t.Fatalf("error while creating new CMM")
 	}
 
 	s3V2 := s3.NewFromConfig(cfg)
 	s3ecV3, err := client.New(s3V2, cmm)
 
 	result, err := s3ecV3.GetObject(ctx, s3.GetObjectInput{
 		Bucket: aws.String(bucket),
 		Key:    aws.String(objectKey),
 	})
 	if err != nil {
 		t.Fatalf("error while decrypting: %v", err)
 	}
```

#### Enable legacy decryption modes
The `enableLegacyUnauthenticatedModes` flag enables the S3 Encryption Client to decrypt
encrypted objects with a fully supported or legacy encryption algorithm.
Version V3 of the S3 Encryption Client uses one of the fully supported wrapping algorithms and the
wrapping key you specify to encrypt and decrypt the data keys. The
`enableLegacyWrappingAlgorithms` flag enables the S3 Encryption Client to decrypt
encrypted data keys with a fully supported or legacy wrapping algorithm.

```go
cmm, err := materials.NewCryptographicMaterialsManager(materials.NewKmsKeyring(kmsClient, kmsKeyArn, func(options *materials.KeyringOptions) {
     options.EnableLegacyWrappingAlgorithms = true
 })
 
 if err != nil {
 	t.Fatalf("error while creating new CMM")
 }
 
 client, err := client.New(s3Client, cmm, func(clientOptions *client.EncryptionClientOptions) {
 		clientOptions.EnableLegacyUnauthenticatedModes = true
 })
 
 if err != nil {
 	// handle error
 }
```

### Legacy Algorithms and Modes
#### Content Encryption
* AES/CBC
#### Key Wrap Encryption
* KMS (without context)
#### Encryption Metadata Storage
* Instruction File

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.
