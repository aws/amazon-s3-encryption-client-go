// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package step3example

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

// Migration Step 3: This example demonstrates how to update your v4 client configuration
// to stop reading objects encrypted with non-key committing algorithms.
//
// This example's purpose is to demonstrate the commitment policy code changes required to
// stop reading objects encrypted with non-key committing algorithms
// and document the behavioral changes that will result from this change.
//
// When starting from a v4 client modeled in "Migration Step 2",
// "Migration Step 3" WILL result in behavioral changes to your application.
// The client will no longer be able to read objects encrypted with non-key committing algorithms.
// Before deploying these changes, you MUST have taken some extra steps 
// to ensure that your system is no longer reading such objects,
// such as re-encrypting them with key committing algorithms.
//
// IMPORTANT: Before deploying the changes in this step, your system should not be reading
// any objects encrypted with non-key committing algorithms.
// The changes in this step will cause such read attempts to fail.
// This means the changes from "Migration Step 2" should have already been deployed to all of your readers
// before you deploy the changes from "Migration Step 3".
//
// Once you complete Step 3, you can be sure that all items being read by your system
// have been encrypted using key committing algorithms.

const CurrentMigrationStep = 3

func RunMigrationExample(bucketName, objectKey, kmsKeyID, region string, sourceStep ...int) error {
	actualSourceStep := CurrentMigrationStep // Default to current step
	if len(sourceStep) > 0 {
		actualSourceStep = sourceStep[0]
	}
	
	fmt.Println("=== S3 Encryption Client v4 Step 3 Example ===")
	fmt.Printf("Current Step: %d (V4 with REQUIRE_ENCRYPT_REQUIRE_DECRYPT)\n", CurrentMigrationStep)
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

	// Create S3 Encryption Client v4 with REQUIRE_ENCRYPT_REQUIRE_DECRYPT commitment policy
	encryptionClient, err := client.New(s3Client, cmm, func(options *client.EncryptionClientOptions) {
		// Migration note: The commitment policy has been changed to REQUIRE_ENCRYPT_REQUIRE_DECRYPT.
		// This change causes the client to stop reading objects encrypted without key committing algorithms.
		// IMPORTANT: Ensure your system is no longer reading such objects before deploying this change.
		// REQUIRE_ENCRYPT_REQUIRE_DECRYPT is also the default commitment policy for v4 clients,
		// so you do not need to set this explicitly.
		options.CommitmentPolicy = commitment.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
	})
	if err != nil {
		return fmt.Errorf("error creating S3 Encryption Client: %v", err)
	}

	fmt.Println("Successfully initialized S3 Encryption Client v4")
	fmt.Println("Commitment Policy: REQUIRE_ENCRYPT_REQUIRE_DECRYPT")
	fmt.Println()

	// Create object keys for PUT and GET operations
	// PUT: Always use current step
	putObjectKey := fmt.Sprintf("%s-step-%d", objectKey, CurrentMigrationStep)
	// GET: Use sourceStep (debug parameter to test cross-compatibility between steps; defaults to 3)
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
