// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	step2example "migration-examples/v4/step2_require_encrypt_allow_decrypt"
)

func main() {
	// Check command line arguments
	if len(os.Args) != 5 {
		fmt.Printf("Usage: %s <bucket-name> <object-key> <kms-key-id> <region>\n", os.Args[0])
		fmt.Printf("Example: %s my-bucket my-key arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012 us-east-2\n", os.Args[0])
		os.Exit(1)
	}

	bucketName := os.Args[1]
	objectKey := os.Args[2]
	kmsKeyID := os.Args[3]
	region := os.Args[4]

	// Run with current step as both source and target (normal operation)
	err := step2example.RunMigrationExample(bucketName, objectKey, kmsKeyID, region)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
