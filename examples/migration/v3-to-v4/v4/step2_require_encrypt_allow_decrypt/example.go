// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package step2example

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/amazon-s3-encryption-client-go/v4/client"
	"github.com/aws/amazon-s3-encryption-client-go/v4/commitment"
	"github.com/aws/amazon-s3-encryption-client-go/v4/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Migration Step 2: This example demonstrates how to update your v4 client configuration
// to start writing objects encrypted with key committing algorithms.
//
// This example's purpose is to demonstrate the commitment policy code changes required to
// start writing objects encrypted with key committing algorithms
// and document the behavioral changes that will result from this change.
//
// When starting from a v4 client modeled in "Migration Step 1",
// "Migration Step 2" WILL result in behavioral changes to your application.
// The client will start writing objects encrypted with key committing algorithms.
//
// IMPORTANT: You MUST have updated your readers to be able to read objects encrypted with key committing algorithms
// before deploying the changes in this step.
// This means deploying the changes from either "Migration Step 0" (if readers are v3 clients)
// or "Migration Step 1" (if readers are v4 clients) to all of your readers
// before deploying the changes from to "Migration Step 2".
//
// Once you deploy this change to your writers, your readers will start seeing
// some objects encrypted with non-key committing algorithms,
// and some objects encrypted with key committing algorithms.
// Because the changes would have already been deployed to all our readers from earlier migration steps,
// we can be sure that our entire system is ready to read both types of objects.
// After deploying these changes but before proceeding to "Migration Step 3",
// you MUST take extra steps to ensure that your system is no longer reading
// objects encrypted with non-key committing algorithms
// (such as re-encrypting any existing objects using key committing algorithms).

const CurrentMigrationStep = 2

func RunMigrationExample(bucketName, objectKey, kmsKeyID, region string, sourceStep ...int) error {
	actualSourceStep := CurrentMigrationStep // Default to current step
	if len(sourceStep) > 0 {
		actualSourceStep = sourceStep[0]
	}
	
	fmt.Println("=== S3 Encryption Client v4 Step 2 Example ===")
	fmt.Printf("Current Step: %d (V4 with REQUIRE_ENCRYPT_ALLOW_DECRYPT)\n", CurrentMigrationStep)
	fmt.Printf("Source Step: %d (reading object written by step %d)\n", actualSourceStep, actualSourceStep)
	fmt.Printf("Bucket: %s\n", bucketName)
	fmt.Printf("Object Key: %s\n", objectKey)
	fmt.Printf("KMS Key ID: %s\n", kmsKeyID)
	fmt.Printf("Region: %s\n", region)
	fmt.Println()

	// Test data for encryption
	testData := "Hello, World! This is a test message for S3 encryption client migration."
	fmt.Printf("Original data: %s\n", testData)
	fmt.Printf("Data length: %d bytes\n", len(testData))
	fmt.Println()

	fmt.Println("--- Initialize S3 Encryption Client v4 ---")

	// Create regular S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("error loading AWS config: %v", err)
	}
	s3Client := s3.NewFromConfig(cfg)

	// Create KMS client
	kmsClient := kms.NewFromConfig(cfg)

	// Create KMS keyring
	keyring := materials.NewKmsKeyring(kmsClient, kmsKeyID)

	// Create Cryptographic Materials Manager
	cmm, err := materials.NewCryptographicMaterialsManager(keyring)
	if err != nil {
		return fmt.Errorf("error creating CMM: %v", err)
	}

	// Create S3 Encryption Client v4 with REQUIRE_ENCRYPT_ALLOW_DECRYPT commitment policy
	encryptionClient, err := client.New(s3Client, cmm, func(options *client.EncryptionClientOptions) {
		// Migration note: The commitment policy has been updated to REQUIRE_ENCRYPT_ALLOW_DECRYPT.
		// This change causes the client to start writing objects encrypted with key committing algorithms.
		// The client will continue to be able to read objects encrypted with either
		// key committing or non-key committing algorithms.
		options.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		return fmt.Errorf("error creating S3 Encryption Client: %v", err)
	}

	fmt.Println("Successfully initialized S3 Encryption Client v4")
	fmt.Println("Commitment Policy: REQUIRE_ENCRYPT_ALLOW_DECRYPT")
	fmt.Println()

	// Create object keys for PUT and GET operations
	// PUT: Always use current step
	putObjectKey := fmt.Sprintf("%s-step-%d", objectKey, CurrentMigrationStep)
	// GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to 2)
	getObjectKey := fmt.Sprintf("%s-step-%d", objectKey, actualSourceStep)

	fmt.Println("--- Encrypt and Upload Object to S3 ---")

	// Upload encrypted object using S3 Encryption Client
	putInput := &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(putObjectKey),
		Body:   strings.NewReader(testData),
	}

	_, err = encryptionClient.PutObject(context.TODO(), putInput)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchBucket") {
			return fmt.Errorf("S3 bucket '%s' does not exist or is not accessible", bucketName)
		} else if strings.Contains(err.Error(), "NotFoundException") {
			return fmt.Errorf("KMS key '%s' not found or not accessible", kmsKeyID)
		} else {
			return fmt.Errorf("error uploading encrypted object: %v", err)
		}
	}

	fmt.Println("Successfully uploaded encrypted object to S3!")
	fmt.Printf("   Bucket: %s\n", bucketName)
	fmt.Printf("   Key: %s\n", putObjectKey)
	fmt.Println()

	fmt.Println("--- Download and Decrypt Object from S3 ---")

	// Download and decrypt object using S3 Encryption Client
	getInput := &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(getObjectKey),
	}

	getResponse, err := encryptionClient.GetObject(context.TODO(), getInput)
	if err != nil {
		return fmt.Errorf("error downloading and decrypting object: %v", err)
	}
	defer getResponse.Body.Close()

	// Read the decrypted data
	decryptedData, err := io.ReadAll(getResponse.Body)
	if err != nil {
		return fmt.Errorf("error reading decrypted data: %v", err)
	}

	fmt.Println("Successfully downloaded and decrypted object from S3!")
	fmt.Printf("   Object size: %d bytes\n", len(decryptedData))
	fmt.Printf("   Decrypted data: %s\n", string(decryptedData))
	fmt.Println()

	fmt.Println("--- Verify Roundtrip Success ---")

	// Verify the roundtrip was successful
	if string(decryptedData) == testData {
		fmt.Println("SUCCESS: Roundtrip encryption/decryption completed successfully!")
		fmt.Println("   Original data matches decrypted data")
		fmt.Println("   Data integrity verified")
	} else {
		return fmt.Errorf("roundtrip failed - data mismatch. Original: %s, Decrypted: %s", testData, string(decryptedData))
	}

	fmt.Println()
	fmt.Println("=== V4 Step 2 Example completed successfully! ===")
	return nil
}
