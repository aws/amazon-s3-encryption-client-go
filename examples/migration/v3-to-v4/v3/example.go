// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v3example

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/amazon-s3-encryption-client-go/v3/commitment"
	"github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Migration Step 0: This example demonstrates use of the S3 Encryption Client for Go v3
// and is the starting state for migrating your data to the v4 client.
//
// This example's purpose is to model behavior of an existing v3 client.
// Subsequent migration steps will demonstrate code changes needed to use the v4 client.
//
// This example configures a v3 client to:
// - Write objects using non-key committing encryption algorithms
// - Read objects encrypted with either key committing algorithms or with non-key committing algorithms
//
// In this configuration, the client can read objects encrypted
// with non-key committing algorithms (written by this v3 client or an in-progress v4 migration),
// as well as objects encrypted by a migrated v4 client
// that is configured to write objects encrypted with key committing algorithms.
// You should ensure you are using the latest version of the v3 client
// that can read objects encrypted with key committing algorithms before proceeding with migration.

const CurrentMigrationStep = 0

func RunMigrationExample(bucketName, objectKey, kmsKeyID, region string, sourceStep ...int) error {
	actualSourceStep := CurrentMigrationStep // Default to current step
	if len(sourceStep) > 0 {
		actualSourceStep = sourceStep[0]
	}
	
	fmt.Println("=== S3 Encryption Client v3 Baseline Example ===")
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

	fmt.Println("--- Initialize S3 Encryption Client v3 ---")

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

	// Create S3 Encryption Client v3 with FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy (default)
	encryptionClient, err := client.New(s3Client, cmm, func(options *client.EncryptionClientOptions) {
		// This is the default commitment policy for v3 clients
		// that can read objects encrypted with key commitment;
		// you do not need to set this explicitly.
		// However, the "commitment" package is only available in v3 versions
		// that can read objects encrypted with key commitment.
		// If you are unsure whether your v3 client version supports this,
		// you can set this explicitly to avoid accidental use of a v3 client
		// that cannot read objects encrypted with key committing algorithms.
		options.CommitmentPolicy = commitment.FORBID_ENCRYPT_ALLOW_DECRYPT
	})
	if err != nil {
		return fmt.Errorf("error creating S3 Encryption Client: %v", err)
	}

	fmt.Println("Successfully initialized S3 Encryption Client v3")
	fmt.Println("Commitment Policy: FORBID_ENCRYPT_ALLOW_DECRYPT")
	fmt.Println()

	// Create object keys for PUT and GET operations
	// PUT: Always use current step
	putObjectKey := fmt.Sprintf("%s-step-%d", objectKey, CurrentMigrationStep)
	// GET: Use actualSourceStep (debug parameter to test cross-compatibility between steps; defaults to current step)
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
	fmt.Println("=== V3 Baseline Example completed successfully! ===")
	return nil
}
