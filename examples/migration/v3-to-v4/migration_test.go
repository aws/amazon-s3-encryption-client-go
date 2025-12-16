// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"testing"

	v3example "migration-examples/v3"
	step1example "migration-examples/v4/step1_forbid_encrypt_allow_decrypt"
	step2example "migration-examples/v4/step2_require_encrypt_allow_decrypt"
	step3example "migration-examples/v4/step3_require_encrypt_require_decrypt"
)

// Test configuration - these should be set via environment variables
var (
	testBucket = getEnvOrDefault("TEST_BUCKET", "s3ec-go-github-test-bucket")
	testKey    = getEnvOrDefault("TEST_KEY", "migration-test")
	testKMSKey = getEnvOrDefault("TEST_KMS_KEY", "arn:aws:kms:us-west-2:370957321024:alias/S3EC-Go-Github-KMS-Key")
	testRegion = getEnvOrDefault("TEST_REGION", "us-west-2")
)

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// runStepExample calls the appropriate step example function directly
func runStepExample(step int, bucket, key, kmsKey, region string) error {
	switch step {
	case 0:
		return v3example.RunMigrationExample(bucket, key, kmsKey, region)
	case 1:
		return step1example.RunMigrationExample(bucket, key, kmsKey, region)
	case 2:
		return step2example.RunMigrationExample(bucket, key, kmsKey, region)
	case 3:
		return step3example.RunMigrationExample(bucket, key, kmsKey, region)
	default:
		return fmt.Errorf("unknown migration step: %d", step)
	}
}

// runStepExampleWithSource calls the appropriate step example function with a source step parameter
func runStepExampleWithSource(step int, sourceStep int, bucket, key, kmsKey, region string) error {
	switch step {
	case 0:
		return v3example.RunMigrationExample(bucket, key, kmsKey, region, sourceStep)
	case 1:
		return step1example.RunMigrationExample(bucket, key, kmsKey, region, sourceStep)
	case 2:
		return step2example.RunMigrationExample(bucket, key, kmsKey, region, sourceStep)
	case 3:
		return step3example.RunMigrationExample(bucket, key, kmsKey, region, sourceStep)
	default:
		return fmt.Errorf("unknown migration step: %d", step)
	}
}

// TestMigrationStep0WriteRead tests that Step 0 (V3) can write and read its own objects
func TestMigrationStep0WriteRead(t *testing.T) {
	t.Log("Testing Step 0 (V3 client) write-read roundtrip")
	
	err := runStepExample(0, testBucket, testKey, testKMSKey, testRegion)
	if err != nil {
		t.Errorf("Step 0 write-read roundtrip failed: %v", err)
	} else {
		t.Log("SUCCESS: Step 0 write-read roundtrip completed")
	}
}

// TestMigrationStep1WriteRead tests that Step 1 (V4 FORBID_ENCRYPT_ALLOW_DECRYPT) can write and read its own objects
func TestMigrationStep1WriteRead(t *testing.T) {
	t.Log("Testing Step 1 (V4 FORBID_ENCRYPT_ALLOW_DECRYPT) write-read roundtrip")
	
	err := runStepExample(1, testBucket, testKey, testKMSKey, testRegion)
	if err != nil {
		t.Errorf("Step 1 write-read roundtrip failed: %v", err)
	} else {
		t.Log("SUCCESS: Step 1 write-read roundtrip completed")
	}
}

// TestMigrationStep2WriteRead tests that Step 2 (V4 REQUIRE_ENCRYPT_ALLOW_DECRYPT) can write and read its own objects
func TestMigrationStep2WriteRead(t *testing.T) {
	t.Log("Testing Step 2 (V4 REQUIRE_ENCRYPT_ALLOW_DECRYPT) write-read roundtrip")
	
	err := runStepExample(2, testBucket, testKey, testKMSKey, testRegion)
	if err != nil {
		t.Errorf("Step 2 write-read roundtrip failed: %v", err)
	} else {
		t.Log("SUCCESS: Step 2 write-read roundtrip completed")
	}
}

// TestMigrationStep3WriteRead tests that Step 3 (V4 REQUIRE_ENCRYPT_REQUIRE_DECRYPT) can write and read its own objects
func TestMigrationStep3WriteRead(t *testing.T) {
	t.Log("Testing Step 3 (V4 REQUIRE_ENCRYPT_REQUIRE_DECRYPT) write-read roundtrip")
	
	err := runStepExample(3, testBucket, testKey, testKMSKey, testRegion)
	if err != nil {
		t.Errorf("Step 3 write-read roundtrip failed: %v", err)
	} else {
		t.Log("SUCCESS: Step 3 write-read roundtrip completed")
	}
}

// TestMigrationCompatibilityMatrix tests cross-compatibility between all migration steps
func TestMigrationCompatibilityMatrix(t *testing.T) {
	// Define the compatibility matrix
	// Each test case specifies: reader step, writer step, expected success
	compatibilityTests := []struct {
		readerStep    int
		writerStep    int
		expectSuccess bool
		description   string
	}{
		// Step 0 (V3) compatibility - can read everything
		{0, 0, true, "V3 reading V3-encrypted object (no key commitment)"},
		{0, 1, true, "V3 reading V4-forbid/allow-encrypted object (no key commitment)"},
		{0, 2, true, "V3 reading V4-require/allow-encrypted object (with key commitment)"},
		{0, 3, true, "V3 reading V4-require/require-encrypted object (with key commitment)"},
		
		// Step 1 (V4 FORBID_ENCRYPT_ALLOW_DECRYPT) compatibility - can read everything
		{1, 0, true, "V4-forbid/allow reading V3-encrypted object (no key commitment)"},
		{1, 1, true, "V4-forbid/allow reading V4-forbid/allow-encrypted object (no key commitment)"},
		{1, 2, true, "V4-forbid/allow reading V4-require/allow-encrypted object (with key commitment)"},
		{1, 3, true, "V4-forbid/allow reading V4-require/require-encrypted object (with key commitment)"},
		
		// Step 2 (V4 REQUIRE_ENCRYPT_ALLOW_DECRYPT) compatibility - can read everything
		{2, 0, true, "V4-require/allow reading V3-encrypted object (no key commitment)"},
		{2, 1, true, "V4-require/allow reading V4-forbid/allow-encrypted object (no key commitment)"},
		{2, 2, true, "V4-require/allow reading V4-require/allow-encrypted object (with key commitment)"},
		{2, 3, true, "V4-require/allow reading V4-require/require-encrypted object (with key commitment)"},
		
		// Step 3 (V4 REQUIRE_ENCRYPT_REQUIRE_DECRYPT) compatibility - can only read objects with key commitment
		{3, 0, false, "V4-require/require reading V3-encrypted object (no key commitment) - SHOULD FAIL"},
		{3, 1, false, "V4-require/require reading V4-forbid/allow-encrypted object (no key commitment) - SHOULD FAIL"},
		{3, 2, true, "V4-require/require reading V4-require/allow-encrypted object (with key commitment)"},
		{3, 3, true, "V4-require/require reading V4-require/require-encrypted object (with key commitment)"},
	}

	for _, tt := range compatibilityTests {
		testName := fmt.Sprintf("Reader_Step%d_Writer_Step%d", tt.readerStep, tt.writerStep)
		t.Run(testName, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)
			
			// Phase 1: Write object using the WRITER step's client
			t.Logf("Phase 1: Writing object using step %d client", tt.writerStep)
			err := runStepExample(tt.writerStep, testBucket, testKey, testKMSKey, testRegion)
			if err != nil {
				t.Fatalf("Failed to write object with step %d: %v", tt.writerStep, err)
			}
			t.Logf("Successfully wrote object with step %d", tt.writerStep)
			
			// Phase 2: Try to read object using the READER step's client
			t.Logf("Phase 2: Reading object using step %d client", tt.readerStep)
			err = runStepExampleWithSource(tt.readerStep, tt.writerStep, testBucket, testKey, testKMSKey, testRegion)
			
			if tt.expectSuccess {
				if err != nil {
					t.Errorf("Expected success but got error: %v", err)
				} else {
					t.Logf("SUCCESS: Step %d successfully processed object from step %d", tt.readerStep, tt.writerStep)
				}
			} else {
				if err == nil {
					t.Errorf("Expected failure but got success - Step %d should not be able to decrypt objects from step %d", tt.readerStep, tt.writerStep)
				} else {
					t.Logf("EXPECTED FAILURE: Step %d correctly failed to process object from step %d: %v", tt.readerStep, tt.writerStep, err)
				}
			}
		})
	}
}

