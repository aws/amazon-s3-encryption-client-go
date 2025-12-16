// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"testing"
)

func TestGenerateNonZeroBytes(t *testing.T) {
	cases := []struct {
		name   string
		length int
	}{
		{
			name:   "small_length",
			length: 12,
		},
		{
			name:   "medium_length",
			length: 28,
		},
		{
			name:   "large_length",
			length: 64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GenerateNonZeroBytes(tc.length)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if len(result) != tc.length {
				t.Errorf("expected length %d, got %d", tc.length, len(result))
			}

			// Verify not all zeros
			allZero := true
			for _, b := range result {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				t.Error("GenerateNonZeroBytes returned all zeros")
			}
		})
	}
}

//= ../specification/s3-encryption/encryption.md#cipher-initialization
//= type=test
//# The client SHOULD validate that the generated IV or Message ID is not zeros.
func TestGenerateNonZeroBytesWithGenerator_AllZeros(t *testing.T) {
	// Mock generator that always returns all zeros
	mockAllZeros := func(n int) ([]byte, error) {
		return make([]byte, n), nil // Returns all zeros
	}

	testCases := []struct {
		name   string
		length int
	}{
		{
			name:   "12_byte_iv",
			length: 12,
		},
		{
			name:   "28_byte_message_id",
			length: 28,
		},
		{
			name:   "16_byte_iv",
			length: 16,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GenerateNonZeroBytesWithGenerator(tc.length, mockAllZeros)

			// Assert that an error is raised after max retries
			if err == nil {
				t.Fatalf("Expected error when generator always returns all zeros for length %d, but got none", tc.length)
			}

			// Assert that the error message indicates retry exhaustion
			expectedErrorMsg := "failed to generate non-zero IV after 3 attempts"
			if err.Error() != expectedErrorMsg {
				t.Errorf("Expected error message '%s', but got '%s'", expectedErrorMsg, err.Error())
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	// Test that the default generator produces different results
	results := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		result, err := generateRandomBytes(16)
		if err != nil {
			t.Fatalf("generateRandomBytes failed: %v", err)
		}
		if len(result) != 16 {
			t.Errorf("Expected length 16, got %d", len(result))
		}
		results[i] = result
	}

	// Check that not all results are identical (very unlikely with proper randomness)
	allSame := true
	for i := 1; i < len(results); i++ {
		if !bytes.Equal(results[0], results[i]) {
			allSame = false
			break
		}
	}

	if allSame {
		t.Errorf("All calls to generateRandomBytes returned identical results, randomness may be compromised")
	}
}
